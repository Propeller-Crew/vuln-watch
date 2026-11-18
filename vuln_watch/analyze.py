"""LLM assessment through the local `claude -p` CLI (uses the logged-in subscription,
no API keys). Deterministic checks run first; Claude adds config-aware reasoning."""
import json
import os
import re
import tempfile

from .util import cfg, log, run

PROMPT = """You are a security triage assistant for ONE Linux server. Decide whether the
vulnerability below affects THIS server, using only the facts given.

Rules:
- "affected": true only if the installed version is in the vulnerable range AND the
  vulnerable feature/module is plausibly in use (see config facts). If version is already
  fixed -> false. If unsure -> null.
- "official_fix_available": true if a fixed version exists in the configured official
  package repository (see candidate version), else false.
- "action": one of "none" (not affected / already fixed), "auto_patch" (official fixed
  package available from an allowed repo and the upgrade is a patch-level update),
  "notify" (human must act: major upgrade, source change, app dependency, reboot, unclear).
- Facts under "decisive" (Ubuntu tracker + version comparison) are authoritative — follow them.
- "verdict": ONE short sentence (max 200 chars) in {lang}, human-friendly, e.g. "HTTP/2 вимкнений, nginx
  уже 1.30.7 — закрито".
- "plan": if action is notify — at most 3 very short steps in {lang} (max 300 chars total),
  no forensic advice, no generic boilerplate; else "".

Answer with ONLY a JSON object:
{{"affected": true|false|null, "official_fix_available": true|false,
  "action": "none|auto_patch|notify", "severity": "critical|high|medium|low|unknown",
  "verdict": "...", "plan": "..."}}

=== VULNERABILITY ===
{vuln}

=== SERVER FACTS ===
{facts}
"""


def _extract_json(text):
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except ValueError:
        return None


def assess(vuln, facts, fallback=None):
    """vuln/facts: dicts. Returns dict (see PROMPT) + 'source': 'claude'|'rules'."""
    c = cfg()["claude"]
    prompt = PROMPT.format(lang="Ukrainian" if cfg().get("language") == "uk" else "English",
                           vuln=json.dumps(vuln, ensure_ascii=False, indent=1)[:12000],
                           facts=json.dumps(facts, ensure_ascii=False, indent=1)[:12000])
    bin_ = c["bin"]
    home = os.path.expanduser(f"~{c['user']}") if c.get("user") else os.path.expanduser("~")
    try:
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o755)
            p = run(["bash", "-c", f"cd {d} && exec {bin_} -p --model {c['model']}"],
                    user=c.get("user"), timeout=c["timeout_sec"], input=prompt,
                    env={"HOME": home})
        res = _extract_json(p.stdout)
        if res and "action" in res:
            res["source"] = "claude"
            return res
        log(f"claude gave no JSON (rc={p.returncode}): {p.stdout[:200]} {p.stderr[:200]}")
    except Exception as e:  # noqa
        log(f"claude failed: {e}")
    out = dict(fallback or {"affected": None, "official_fix_available": False,
                            "action": "notify", "severity": "unknown",
                            "verdict": "Не вдалося оцінити автоматично — перевір вручну.",
                            "plan": ""})
    out["source"] = "rules"
    return out
