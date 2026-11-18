"""vuln-watch CLI."""
import argparse
import json
import os
import sys
import time

from . import feeds, health, inventory, notify, patch, scan
from .util import lock, log, load_state, save_state, read_events, append_event


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
    notify.send(f"[сухий прогін] nginx {a.cve} — {advs[0]['title']}\n{res['verdict']}", dry_run=True)


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
        notify.send("🔴 Після нічного unattended-upgrades щось впало:\n"
                    + "\n".join("• " + p for p in probs[:15])
                    + "\nДив. /var/log/unattended-upgrades/ та `journalctl -u apt-daily-upgrade`.")


def cmd_digest(a):
    ev = read_events(time.time() - 7 * 86400)
    pat = [e for e in ev if e["kind"] == "patched"]
    rb = [e for e in ev if e["kind"] == "rollback"]
    osv = [e for e in ev if e["kind"] == "osv"]
    rs = patch.reboot_status()
    lines = ["🗓 Тижневий дайджест безпеки"]
    lines.append(f"Автооновлень: {len(pat)}" + (" — " + "; ".join(p for e in pat for p in e["pkgs"])[:600] if pat else ""))
    lines.append(f"Відкатів: {len(rb)}")
    if osv:
        lines.append(f"Вразливості в залежностях апок: {osv[-1]['total']} (high/critical: {osv[-1]['high_crit']})")
    if rs:
        lines.append(f"🔁 Досі потрібен ребут: ядро {rs['running_kernel']} ({', '.join(rs['pkgs'][:5])})")
    import apt
    c = apt.Cache()
    pend = sorted({o.origin for p in c if p.is_installed and p.is_upgradable
                   for o in p.candidate.origins} - {"Ubuntu"})
    if pend:
        lines.append("Не-security оновлення з інших репо чекають ручного рішення: " + ", ".join(pend))
    h = health.snapshot()
    lines.append("Стан: " + health.summary(h))
    notify.send("\n".join(lines), dry_run=a.dry_run)


def cmd_notify_test(a):
    me = notify.whoami()
    print("bot:", me)
    if a.expect and (not me or me["username"] != a.expect):
        sys.exit(f"bot mismatch: expected {a.expect}")
    if not a.check_only:
        notify.send(a.text or "Тестове повідомлення: vuln-watch налаштований і стежить за вразливостями.")


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
    p = sp.add_parser("digest"); p.add_argument("--dry-run", action="store_true"); p.set_defaults(f=cmd_digest)
    p = sp.add_parser("notify-test"); p.add_argument("--expect"); p.add_argument("--text")
    p.add_argument("--check-only", action="store_true"); p.set_defaults(f=cmd_notify_test)
    p = sp.add_parser("inventory"); p.set_defaults(f=cmd_inventory)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
