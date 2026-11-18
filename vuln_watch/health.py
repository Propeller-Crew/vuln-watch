"""Liveness snapshot: every nginx vhost (via 127.0.0.1), systemd, pm2, docker.
"nginx -t passed" is not enough — we compare real HTTP answers before/after."""
import json
import time
from concurrent.futures import ThreadPoolExecutor

from . import inventory
from .util import cfg, run, log


def _probe(name, ssl):
    def curl(scheme, port):
        p = run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15",
                 "--resolve", f"{name}:{port}:127.0.0.1", f"{scheme}://{name}/"], timeout=30)
        try:
            return int(p.stdout.strip() or 0)
        except ValueError:
            return 0
    code = curl("https", 443) if ssl else 0
    if code == 0:
        code = curl("http", 80)
    return code


def snapshot():
    snap = {"ts": time.time()}
    names = inventory.server_names()
    with ThreadPoolExecutor(8) as ex:
        codes = list(ex.map(lambda nv: _probe(*nv), names))
    snap["vhosts"] = {n: c for (n, _), c in zip(names, codes)}
    for u in cfg()["health"]["extra_urls"]:
        p = run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", u])
        snap["vhosts"][u] = int(p.stdout.strip() or 0)

    p = run(["systemctl", "list-units", "--state=failed", "--plain", "--no-legend", "--all"])
    snap["failed_units"] = sorted(l.split()[0] for l in p.stdout.splitlines() if l.strip())
    p = run(["systemctl", "is-active", "nginx"])
    snap["nginx_active"] = p.stdout.strip()

    snap["pm2"] = {}
    for u in cfg()["health"]["pm2_users"]:
        p = run(["bash", "-lc", "pm2 jlist"], user=u, timeout=60)
        try:
            start = p.stdout.index("[")
            procs = json.loads(p.stdout[start:])
            snap["pm2"][u] = {x["name"]: x["pm2_env"]["status"] for x in procs}
        except (ValueError, KeyError):
            snap["pm2"][u] = None
    if cfg()["health"]["check_docker"]:
        p = run(["docker", "ps", "--format", "{{.Names}}"])
        snap["docker"] = sorted(p.stdout.split()) if p.returncode == 0 else None
    return snap


def _bad(code):
    return code == 0 or code >= 500


def regressions(before, after):
    """List of human-readable problems that appeared after the change."""
    out = []
    for n, c in before["vhosts"].items():
        a = after["vhosts"].get(n, 0)
        if not _bad(c) and _bad(a):
            out.append(f"сайт {n}: {c} → {a}")
    if before.get("nginx_active") == "active" and after.get("nginx_active") != "active":
        out.append(f"nginx: {after.get('nginx_active')}")
    for u in sorted(set(after["failed_units"]) - set(before["failed_units"])):
        out.append(f"systemd {u}: failed")
    for user, procs in (before.get("pm2") or {}).items():
        now = (after.get("pm2") or {}).get(user) or {}
        for name, st in (procs or {}).items():
            if st == "online" and now.get(name) != "online":
                out.append(f"pm2 {user}/{name}: {now.get(name, 'missing')}")
    if before.get("docker") is not None and after.get("docker") is not None:
        for c in sorted(set(before["docker"]) - set(after["docker"])):
            out.append(f"docker {c}: stopped")
    return out


def wait_healthy(before):
    """Re-check a few times (apps may be restarting). Returns (after, problems)."""
    h = cfg()["health"]
    after, probs = None, ["not checked"]
    for i in range(h["retries"]):
        if i:
            time.sleep(h["retry_delay_sec"])
        after = snapshot()
        probs = regressions(before, after)
        if not probs:
            return after, []
        log(f"health attempt {i + 1}: {len(probs)} problems: {probs[:3]}")
    return after, probs


def summary(s):
    bad = {n: c for n, c in s["vhosts"].items() if _bad(c)}
    pm = {u: sum(1 for v in (p or {}).values() if v == "online") for u, p in s["pm2"].items()}
    return (f"vhosts {len(s['vhosts']) - len(bad)}/{len(s['vhosts'])} ok"
            + (f" (bad: {bad})" if bad else "")
            + f"; failed units: {s['failed_units'] or 'none'}; pm2 online: {pm}"
            + (f"; docker: {len(s['docker'])}" if s.get("docker") is not None else ""))
