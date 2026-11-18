"""Safe auto-patching of official security updates.

backup configs + old .debs -> upgrade (confold) -> undo any /etc/nginx drift ->
nginx -t -> live health vs baseline -> on regression: roll back + notify.
Never reboots; only reports that a reboot is needed."""
import fnmatch
import glob
import hashlib
import os
import re
import shutil
import tarfile
import time

from . import health, notify
from .util import cfg, log, run, load_state, save_state, append_event, dpkg_cmp, tr

APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a",
           "NEEDRESTART_SUSPEND": ""}
DPKG_OPTS = ["-o", "DPkg::Lock::Timeout=900", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]
WATCHED_DIRS = ["/etc/nginx"]


# ---------- candidate selection ----------

def _minor(v):
    m = re.match(r"(?:\d+:)?(\d+)\.(\d+)", v)
    return m.groups() if m else None


def _allowed(ver, installed_ver):
    for o in ver.origins:
        for rule in cfg()["auto_patch"]["origins"]:
            if o.origin != rule["origin"]:
                continue
            if rule.get("archive_suffix") and not (o.archive or "").endswith(rule["archive_suffix"]):
                continue
            if rule.get("same_minor_only") and _minor(ver.version) != _minor(installed_ver):
                continue
            return f"{o.origin}/{o.archive}"
    return None


def candidates(only=None, any_origin=False):
    """[(name, installed, target, origin)] — highest allowed version per package."""
    import apt
    cache = apt.Cache()
    blocked = load_state("blocked.json")
    never = cfg()["auto_patch"]["never"]
    out = []
    for pkg in cache:
        if not pkg.is_installed or (only and pkg.name not in only):
            continue
        if any(fnmatch.fnmatch(pkg.name, pat) for pat in never):
            continue
        inst = pkg.installed.version
        for ver in sorted(pkg.versions, reverse=True):
            if not dpkg_cmp(ver.version, "gt", inst):
                break
            origin = "any" if any_origin else _allowed(ver, inst)
            if origin and blocked.get(pkg.name) != ver.version:
                out.append((pkg.name, inst, ver.version, origin, pkg.installed.architecture))
                break
    return out


# ---------- backup / restore ----------

def _tree_hashes(d):
    out = {}
    for root, _, files in os.walk(d):
        for f in files:
            p = os.path.join(root, f)
            try:
                if os.path.islink(p):
                    out[p] = "link:" + os.readlink(p)
                else:
                    with open(p, "rb") as fh:
                        out[p] = hashlib.sha256(fh.read()).hexdigest()
            except OSError:
                pass
    return out


def _conffiles(pkgs):
    files = []
    for name in pkgs:
        p = run(["dpkg-query", "-W", "-f=${Conffiles}", name])
        files += [l.split()[0] for l in p.stdout.splitlines() if l.strip()]
    return [f for f in files if os.path.exists(f)]


def backup(targets, bdir):
    os.makedirs(os.path.join(bdir, "debs"), exist_ok=True)
    names = [t[0] for t in targets]
    paths = sorted(set(WATCHED_DIRS + _conffiles(names)))
    with tarfile.open(os.path.join(bdir, "etc.tgz"), "w:gz") as tar:
        for p in paths:
            if os.path.exists(p):
                tar.add(p)
    no_deb = []
    for name, inst, _, _, arch in targets:
        short = name.split(":")[0]
        fn = f"{short}_{inst.replace(':', '%3a')}_{arch}.deb"
        cached = os.path.join("/var/cache/apt/archives", fn)
        dst = os.path.join(bdir, "debs", fn)
        if os.path.exists(cached):
            shutil.copy2(cached, dst)
            continue
        p = run(["apt-get", "download", f"{name}={inst}"], timeout=300)
        got = glob.glob(f"{short}_*_{arch}.deb")
        if p.returncode == 0 and got:
            shutil.move(got[0], dst)
            continue
        p = run(["dpkg-repack", name], timeout=600)
        got = glob.glob(f"{short}_*_{arch}.deb")
        if p.returncode == 0 and got:
            shutil.move(got[0], dst)
        else:
            no_deb.append(name)
    return {"paths": paths, "hashes": {d: _tree_hashes(d) for d in WATCHED_DIRS}, "no_deb": no_deb}


def undo_config_drift(meta, bdir):
    """If a package changed/added files in watched dirs, move them aside and restore."""
    drift = []
    for d, before in meta["hashes"].items():
        now = _tree_hashes(d)
        changed = [p for p in now if before.get(p) != now[p]]
        removed = [p for p in before if p not in now]
        if not changed and not removed:
            continue
        aside = os.path.join(bdir, "drift")
        for p in changed:
            tgt = os.path.join(aside, p.lstrip("/"))
            os.makedirs(os.path.dirname(tgt), exist_ok=True)
            shutil.move(p, tgt)
        with tarfile.open(os.path.join(bdir, "etc.tgz")) as tar:
            members = [m for m in tar.getmembers()
                       if "/" + m.name in set(changed) | set(removed)]
            tar.extractall("/", members=members, filter="fully_trusted")
        drift += changed + removed
    return drift


def restore_configs(bdir):
    aside = os.path.join(bdir, "after-upgrade")
    for d in WATCHED_DIRS:
        if os.path.exists(d):
            tgt = os.path.join(aside, d.lstrip("/"))
            os.makedirs(os.path.dirname(tgt), exist_ok=True)
            shutil.move(d, tgt)
    with tarfile.open(os.path.join(bdir, "etc.tgz")) as tar:
        tar.extractall("/", filter="fully_trusted")


# ---------- main flow ----------

def _nginx_ok():
    p = run(["nginx", "-t"])
    return p.returncode == 0, (p.stderr or p.stdout).strip()[-400:]


def _nginx_binary_stale():
    p = run(["systemctl", "show", "-p", "MainPID", "--value", "nginx"])
    pid = p.stdout.strip()
    try:
        return pid != "0" and "(deleted)" in os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return False


def reboot_status():
    if not os.path.exists("/var/run/reboot-required"):
        return None
    pkgs = []
    if os.path.exists("/var/run/reboot-required.pkgs"):
        pkgs = sorted(set(open("/var/run/reboot-required.pkgs").read().split()))
    return {"running_kernel": os.uname().release, "pkgs": pkgs}


def run_patch(dry_run=False, only=None, any_origin=False, inject_failure=False, quiet_ok=False):
    """Returns result dict. Sends Telegram only when something changed or broke."""
    run(["apt-get", "-o", "DPkg::Lock::Timeout=900", "update", "-qq"], timeout=900, env=APT_ENV)
    targets = candidates(only=only, any_origin=any_origin)
    if not targets:
        log("no allowed upgrades")
        return {"status": "nothing"}
    spec = [f"{n}={v}" for n, _, v, _, _ in targets]
    log("targets: " + ", ".join(f"{n} {i}→{v} [{o}]" for n, i, v, o, _ in targets))

    sim = run(["apt-get", "-s", "install", "--only-upgrade", "-y"] + DPKG_OPTS + spec, env=APT_ENV)
    removals = re.findall(r"^Remv (\S+)", sim.stdout, re.M)
    if sim.returncode != 0 or removals:
        msg = tr(f"⚠️ Оновлення безпеки НЕ поставлені автоматично: apt хоче видалити пакети "
                 f"{removals or ''} або симуляція впала.\nПакети: {', '.join(spec)}\n"
                 f"План: подивитись `apt-get -s install --only-upgrade {' '.join(spec)}` вручну.",
                 f"⚠️ Security updates were NOT installed automatically: apt wants to remove packages "
                 f"{removals or ''} or the simulation failed.\nPackages: {', '.join(spec)}\n"
                 f"Plan: review `apt-get -s install --only-upgrade {' '.join(spec)}` manually.")
        notify.send(msg, dry_run=dry_run)
        return {"status": "refused", "removals": removals}
    if dry_run:
        print(sim.stdout[-3000:])
        return {"status": "dry-run", "targets": targets}

    bdir = os.path.join(cfg()["backup_dir"], time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(bdir, exist_ok=True)
    os.chdir(bdir)
    before = health.snapshot()
    log("baseline: " + health.summary(before))
    meta = backup(targets, bdir)

    up = run(["apt-get", "install", "--only-upgrade", "-y"] + DPKG_OPTS + spec,
             env=APT_ENV, timeout=3600)
    with open(os.path.join(bdir, "apt.log"), "w") as f:
        f.write(up.stdout + "\n" + up.stderr)
    drift = undo_config_drift(meta, bdir)
    if drift:
        log(f"config drift undone: {drift}")
    nginx_touched = any(n.startswith("nginx") for n, *_ in targets) or drift
    problems = []
    if up.returncode != 0:
        problems.append(tr(f"apt-get завершився з кодом {up.returncode}", f"apt-get exited with code {up.returncode}"))
    if nginx_touched:
        ok, out = _nginx_ok()
        if not ok:
            problems.append(f"nginx -t: {out}")
        elif _nginx_binary_stale() or drift:
            run(["systemctl", "restart", "nginx"])
    after, probs = health.wait_healthy(before)
    problems += probs
    if inject_failure:
        problems.append(tr("ТЕСТ: штучна поломка для перевірки відкату", "TEST: injected failure to verify rollback"))

    upgraded = [f"{n} {i} → {v}" for n, i, v, _, _ in targets]
    result = {"targets": upgraded, "backup": bdir, "drift": drift}
    if not problems:
        append_event("patched", {"pkgs": upgraded})
        result["status"] = "ok"
        msg = tr("✅ Автоматично поставлено оновлення безпеки:\n", "✅ Security updates installed automatically:\n") + "\n".join("• " + u for u in upgraded)
        if drift:
            msg += tr("\n\nПакет переписав конфіги — повернув наші: ", "\n\nThe package changed configs — restored ours: ") + ", ".join(drift)
        msg += tr("\n\nПеревірка: ", "\n\nCheck: ") + health.summary(after)
        msg += _reboot_line()
        if not quiet_ok:
            notify.send(msg)
        return result

    # ---------- rollback ----------
    log(f"ROLLBACK: {problems}")
    debs = sorted(glob.glob(os.path.join(bdir, "debs", "*.deb")))
    rb = run(["dpkg", "-i", "--force-confold", "--force-downgrade"] + debs, timeout=1800,
             env=APT_ENV) if debs else None
    restore_configs(bdir)
    ok, out = _nginx_ok()
    if ok:
        run(["systemctl", "restart", "nginx"])
    for u in set(after["failed_units"]) - set(before["failed_units"]) if after else []:
        run(["systemctl", "restart", u])
    for user, procs in (before.get("pm2") or {}).items():
        now = ((after or {}).get("pm2") or {}).get(user) or {}
        for name, st in (procs or {}).items():
            if st == "online" and now.get(name) != "online":
                run(["bash", "-lc", f"pm2 restart {name!r}"], user=user)
    final, still = health.wait_healthy(before)
    versions = {n: run(["dpkg-query", "-W", "-f=${Version}", n]).stdout for n, *_ in targets}
    rolled = all(versions[n] == i for n, i, *_ in targets if n not in meta["no_deb"])
    blocked = load_state("blocked.json")
    if not inject_failure:
        for n, _, v, _, _ in targets:
            blocked[n] = v
        save_state("blocked.json", blocked)
    append_event("rollback", {"pkgs": upgraded, "problems": problems, "recovered": not still})
    result.update(status="rolled_back", problems=problems, still_broken=still,
                  versions_after=versions, versions_restored=rolled)
    msg = (tr("🔴 Оновлення зламало сервіси — ВІДКОТИВ.\n", "🔴 The update broke services — ROLLED BACK.\n")
           + "\n".join("• " + u for u in upgraded)
           + tr("\n\nЩо впало:\n", "\n\nWhat broke:\n") + "\n".join("• " + p for p in problems[:15])
           + tr("\n\nПісля відкату: ", "\n\nAfter rollback: ")
           + (tr("усе живе ✅", "all healthy ✅") if not still
              else tr("ДОСІ ПРОБЛЕМИ: ", "STILL BROKEN: ") + "; ".join(still[:10]))
           + tr("\nВерсії повернуто: ", "\nVersions restored: ")
           + (tr("так", "yes") if rolled else tr("НІ", "NO")) + f" {versions}"
           + (tr("\nНемає старого .deb для: ", "\nNo old .deb for: ") + str(meta['no_deb']) if meta['no_deb'] else "")
           + tr("\nБекап: ", "\nBackup: ") + bdir
           + tr("\nЦі версії більше автоматично не ставлю, поки не вийде новіша.",
                "\nThese versions are blocked from auto-install until a newer one appears."))
    notify.send(msg)
    return result


def _reboot_line():
    rs = reboot_status()
    if not rs:
        return ""
    st = load_state("reboot.json")
    key = ",".join(rs["pkgs"])
    if st.get("notified") == key:
        return ""
    save_state("reboot.json", {"notified": key, "ts": time.time()})
    return tr(f"\n\n🔁 Потрібен ребут (зробиш сам у тихий час): ядро зараз {rs['running_kernel']}, "
              f"пакети: {', '.join(rs['pkgs'][:8])}",
              f"\n\n🔁 Reboot needed (do it yourself at a quiet time): running kernel {rs['running_kernel']}, "
              f"packages: {', '.join(rs['pkgs'][:8])}")
