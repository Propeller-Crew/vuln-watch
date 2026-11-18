"""Telegram notifications (token never printed)."""
import json
import os
import socket
import urllib.parse
import urllib.request

from .util import cfg, log, append_event


def _creds():
    t = cfg()["telegram"]
    env = {}
    if os.path.exists(t["env_file"]):
        with open(t["env_file"]) as f:
            for line in f:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.strip().split("=", 1)
                    env[k] = v.strip().strip('"').strip("'")
    token = os.environ.get(t["token_var"]) or env.get(t["token_var"])
    chat = os.environ.get(t["chat_var"]) or env.get(t["chat_var"])
    return token, chat


def _api(method, token, params=None):
    data = urllib.parse.urlencode(params).encode() if params else None
    with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/{method}",
                                data=data, timeout=30) as r:
        return json.loads(r.read())


def whoami():
    token, chat = _creds()
    if not token:
        return None
    me = _api("getMe", token)["result"]
    return {"username": me.get("username"), "chat_set": bool(chat)}


def send(text, dry_run=False):
    host = cfg().get("host_label") or socket.gethostname()
    text = f"🛡 vuln-watch @ {host}\n\n{text}"
    if dry_run or os.environ.get("VULN_WATCH_DRY_RUN"):
        print("----- [dry-run] Telegram message -----\n" + text + "\n--------------------------------------")
        return True
    token, chat = _creds()
    if not token or not chat:
        log("telegram not configured; message:\n" + text)
        return False
    ok = True
    for i in range(0, len(text), 3900):
        try:
            _api("sendMessage", token, {"chat_id": chat, "text": text[i:i + 3900],
                                        "disable_web_page_preview": "true"})
        except Exception as e:  # noqa
            log(f"telegram send failed: {type(e).__name__}")
            ok = False
    append_event("notify", {"chars": len(text), "ok": ok})
    return ok
