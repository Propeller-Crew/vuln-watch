"""vuln-watch CLI."""
import argparse
import json
import os
import sys
import time

from . import feeds, health, inventory, notify, patch, scan
from .util import lock, log, load_state, save_state, read_events, append_event, tr


def cmd_scan(a):
    with lock():
        print(json.dumps(scan.run_scan(dry_run=a.dry_run), ensure_ascii=False, default=str))


def cmd_patch(a):
    with lock():
        r = patch.run_patch(dry_run=a.dry_run, only=set(a.only) if a.only else None)
        print(json.dumps(r, ensure_ascii=False, default=str))


def cmd_test_rollback(a):
    """Upgrade one harmless package, inject a failure, verify rollback."""
    with lock():
        r = patch.run_patch(only={a.package}, any_origin=True, inject_failure=True)
        print(json.dumps(r, ensure_ascii=False, default=str, indent=1))
        ok = r.get("status") == "rolled_back" and r.get("versions_restored") and not r.get("still_broken")
        print("ROLLBACK TEST:", "PASSED" if ok else "FAILED")
        sys.exit(0 if ok else 1)


def cmd_assess(a):
    """Dry run one nginx advisory by CVE (no patch, message printed only)."""
    inv = inventory.collect(full=False)
    advs = [x for x in feeds.nginx_advisories() if a.cve in x["cves"]]
    if not advs:
        sys.exit(f"{a.cve} not found on nginx.org")
    res = scan.assess_nginx(advs[0], inv)
    print(json.dumps(res, ensure_ascii=False, indent=1))
    notify.send(tr("[сухий прогін]", "[dry run]") + f" nginx {a.cve} — {advs[0]['title']}\n{res['verdict']}", dry_run=True)


def cmd_health(a):
    s = health.snapshot()
    print(json.dumps(s, indent=1) if a.json else health.summary(s))


def cmd_unattended(a):
    """Hooks around Ubuntu's apt-daily-upgrade (unattended-upgrades): baseline before,
    compare after, notify on regression (it has no rollback of its own)."""
    if a.phase == "pre":
        save_state("ua_baseline.json", health.snapshot())
        return
    before = load_state("ua_baseline.json")
    if not before:
        return
    after, probs = health.wait_healthy(before)
    if probs:
        append_event("ua_regression", {"problems": probs})
        notify.send(tr("🔴 Після нічного unattended-upgrades щось впало:\n",
                       "🔴 Something broke after nightly unattended-upgrades:\n")
                    + "\n".join("• " + p for p in probs[:15])
                    + tr("\nДив. /var/log/unattended-upgrades/ та `journalctl -u apt-daily-upgrade`.",
                         "\nSee /var/log/unattended-upgrades/ and `journalctl -u apt-daily-upgrade`."))


def cmd_reboot(a):
    """Planned reboot window: optional guard command (exit 0 = ok to reboot), pm2 save,
    health baseline, reboot. The post-boot check runs from vuln-watch-postboot.service."""
    import subprocess
    r = __import__("vuln_watch.util", fromlist=["cfg"]).cfg().get("reboot", {})
    cold = health.cold_start_problems()
    if cold:
        log("cold-start check failed: " + "; ".join(cold))
        if not a.dry_run:
            notify.send(tr("⛔ Плановий ребут скасовано: ці апки зараз працюють з пам'яті, але після ребуту не піднімуться:\n",
                           "⛔ Planned reboot cancelled: these apps run from memory now but would not start after a reboot:\n")
                        + "\n".join("• " + c for c in cold[:15])
                        + tr("\nПерезбери їх, потім: sudo vuln-watch reboot", "\nRebuild them, then: sudo vuln-watch reboot"))
        return
    deadline = time.time() + 60 * r.get("max_wait_min", 120)
    guard = r.get("guard_cmd")
    while guard and subprocess.run(guard, shell=True).returncode != 0:
        if time.time() > deadline:
            notify.send(tr("⏸ Плановий ребут скасовано: запобіжник не дозволив до кінця вікна. "
                           "Запусти пізніше: sudo vuln-watch reboot",
                           "⏸ Planned reboot cancelled: the guard did not allow it before the window closed. "
                           "Run later: sudo vuln-watch reboot"))
            return
        log("guard says wait; retry in 5 min")
        time.sleep(300)
    for u in __import__("vuln_watch.util", fromlist=["cfg"]).cfg()["health"]["pm2_users"]:
        from .util import run
        run(["bash", "-lc", "pm2 save"], user=u)
    snap = health.snapshot()
    log("baseline: " + health.summary(snap))
    if a.dry_run:
        print("dry-run: would save baseline and reboot now")
        return
    save_state("reboot_baseline.json", snap)
    append_event("reboot", {"kernel_before": os.uname().release})
    os.execvp("systemctl", ["systemctl", "reboot"])


def cmd_postboot(a):
    from .util import state_path
    p = state_path("reboot_baseline.json")
    if not os.path.exists(p):
        return
    before = load_state("reboot_baseline.json")
    up = float(open("/proc/uptime").read().split()[0])
    if up < 120:
        time.sleep(120 - up)
    after, probs = health.wait_healthy(before, retries=20, delay=30)
    os.replace(p, p + f".done-{time.strftime('%Y%m%d-%H%M%S')}")
    down = int(time.time() - before["ts"] - float(open("/proc/uptime").read().split()[0]))
    rs = patch.reboot_status()
    msg = (tr(f"🔁 Ребут зроблено. Ядро тепер {os.uname().release}, сервер був недоступний ~{max(down, 0)} с.\n",
              f"🔁 Reboot done. Kernel is now {os.uname().release}, server was down ~{max(down, 0)} s.\n")
           + (tr("✅ Усе піднялося: ", "✅ Everything is back: ") + health.summary(after) if not probs else
              tr("🔴 Не піднялося:\n", "🔴 Did not come back:\n") + "\n".join("• " + x for x in probs[:15])))
    if rs:
        msg += tr("\nЩе просить ребут: ", "\nStill requests a reboot: ") + ", ".join(rs['pkgs'][:5])
    notify.send(msg)


def cmd_digest(a):
    ev = read_events(time.time() - 7 * 86400)
    pat = [e for e in ev if e["kind"] == "patched"]
    rb = [e for e in ev if e["kind"] == "rollback"]
    osv = [e for e in ev if e["kind"] == "osv"]
    rs = patch.reboot_status()
    lines = [tr("🗓 Тижневий дайджест безпеки", "🗓 Weekly security digest")]
    lines.append(tr("Автооновлень: ", "Auto-updates: ") + f"{len(pat)}" + (" — " + "; ".join(p for e in pat for p in e["pkgs"])[:600] if pat else ""))
    lines.append(tr("Відкатів: ", "Rollbacks: ") + str(len(rb)))
    if osv:
        lines.append(tr("Вразливості в залежностях апок: ", "Vulnerabilities in app dependencies: ")
                     + f"{osv[-1]['total']} (high/critical: {osv[-1]['high_crit']})")
    if rs:
        lines.append(tr("🔁 Досі потрібен ребут: ядро ", "🔁 Reboot still needed: kernel ")
                     + f"{rs['running_kernel']} ({', '.join(rs['pkgs'][:5])})")
    import apt
    c = apt.Cache()
    pend = sorted({o.origin for p in c if p.is_installed and p.is_upgradable
                   for o in p.candidate.origins} - {"Ubuntu"})
    if pend:
        lines.append(tr("Не-security оновлення з інших репо чекають ручного рішення: ",
                        "Non-security updates from other repos await a manual decision: ") + ", ".join(pend))
    cold = health.cold_start_problems()
    if cold:
        lines.append(tr("⚠️ Не піднімуться після рестарту: ", "⚠️ Would not start after a restart: ") + "; ".join(cold[:5]))
    h = health.snapshot()
    lines.append(tr("Стан: ", "Status: ") + health.summary(h))
    notify.send("\n".join(lines), dry_run=a.dry_run)


def cmd_notify_test(a):
    me = notify.whoami()
    print("bot:", me)
    if a.expect and (not me or me["username"] != a.expect):
        sys.exit(f"bot mismatch: expected {a.expect}")
    if not a.check_only:
        notify.send(a.text or tr("Тестове повідомлення: vuln-watch налаштований і стежить за вразливостями.",
                                 "Test message: vuln-watch is set up and watching for vulnerabilities."))


def cmd_inventory(a):
    inv = inventory.collect(full=True)
    print(json.dumps({"dpkg_packages": len(inv["dpkg"]), "runtimes": inv["runtimes"],
                      "docker": inv["docker"], "nginx": inv["nginx"],
                      "lockfiles": {k: len(v) for k, v in inv["lockfiles"].items()}},
                     indent=1, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser(prog="vuln-watch")
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("scan"); p.add_argument("--dry-run", action="store_true"); p.set_defaults(f=cmd_scan)
    p = sp.add_parser("patch"); p.add_argument("--dry-run", action="store_true")
    p.add_argument("--only", nargs="*"); p.set_defaults(f=cmd_patch)
    p = sp.add_parser("test-rollback"); p.add_argument("package"); p.set_defaults(f=cmd_test_rollback)
    p = sp.add_parser("assess"); p.add_argument("cve"); p.set_defaults(f=cmd_assess)
    p = sp.add_parser("health"); p.add_argument("--json", action="store_true"); p.set_defaults(f=cmd_health)
    p = sp.add_parser("unattended"); p.add_argument("phase", choices=["pre", "post"]); p.set_defaults(f=cmd_unattended)
    p = sp.add_parser("reboot"); p.add_argument("--dry-run", action="store_true"); p.set_defaults(f=cmd_reboot)
    p = sp.add_parser("postboot"); p.set_defaults(f=cmd_postboot)
    p = sp.add_parser("digest"); p.add_argument("--dry-run", action="store_true"); p.set_defaults(f=cmd_digest)
    p = sp.add_parser("notify-test"); p.add_argument("--expect"); p.add_argument("--text")
    p.add_argument("--check-only", action="store_true"); p.set_defaults(f=cmd_notify_test)
    p = sp.add_parser("inventory"); p.set_defaults(f=cmd_inventory)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
