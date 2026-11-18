"""Shared helpers: config, state, logging, subprocess, HTTP."""
import fcntl
import json
import os
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager

CONFIG_PATH = os.environ.get("VULN_WATCH_CONFIG", "/etc/vuln-watch/config.json")
UA = "vuln-watch/1.0 (+https://github.com/)"

DEFAULTS = {
    "release": "noble",
    "state_dir": "/var/lib/vuln-watch",
    "backup_dir": "/var/backups/vuln-watch",
    "auto_patch": {"origins": [], "never": []},
    "health": {"pm2_users": [], "check_docker": True, "retries": 6,
               "retry_delay_sec": 10, "extra_urls": []},
    "inventory": {"lockfile_roots": ["/opt"], "lockfile_max_depth": 4},
    "claude": {"user": None, "bin": "claude", "model": "sonnet", "timeout_sec": 300},
    "telegram": {"env_file": "/etc/vuln-watch/telegram.env",
                 "token_var": "TELEGRAM_BOT_TOKEN", "chat_var": "TELEGRAM_CHAT_ID"},
}


def _merge(a, b):
    out = dict(a)
    for k, v in b.items():
        out[k] = _merge(a[k], v) if isinstance(v, dict) and isinstance(a.get(k), dict) else v
    return out


_cfg = None


def cfg():
    global _cfg
    if _cfg is None:
        data = {}
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH) as f:
                data = json.load(f)
        _cfg = _merge(DEFAULTS, data)
    return _cfg


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, file=sys.stderr, flush=True)


def run(cmd, check=False, timeout=600, env=None, input=None, user=None):
    """Run a command (list). Returns CompletedProcess with text output."""
    if user and os.geteuid() == 0:
        cmd = ["runuser", "-u", user, "--"] + cmd
    e = dict(os.environ)
    if env:
        e.update(env)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       env=e, input=input)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> {p.returncode}: {p.stderr.strip()[:500]}")
    return p


def http_get(url, timeout=60, as_json=False, data=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA}, data=data)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    return json.loads(body) if as_json else body.decode("utf-8", "replace")


def state_path(name):
    d = cfg()["state_dir"]
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def load_state(name, default=None):
    p = state_path(name)
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {} if default is None else default


def save_state(name, data):
    p = state_path(name)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, p)


def append_event(kind, payload):
    """Append to events.jsonl — used by the weekly digest."""
    with open(state_path("events.jsonl"), "a") as f:
        f.write(json.dumps({"ts": time.time(), "kind": kind, **payload},
                           ensure_ascii=False) + "\n")


def read_events(since_ts):
    p = state_path("events.jsonl")
    if not os.path.exists(p):
        return []
    out = []
    with open(p) as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("ts", 0) >= since_ts:
                out.append(e)
    return out


@contextmanager
def lock(name="vuln-watch"):
    path = f"/run/{name}.lock" if os.geteuid() == 0 else state_path(f"{name}.lock")
    f = open(path, "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()


def dpkg_cmp(a, op, b):
    """op: lt, le, eq, ge, gt"""
    return run(["dpkg", "--compare-versions", a, op, b]).returncode == 0
