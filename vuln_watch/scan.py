"""Collect new advisories -> match with inventory -> decide -> patch or notify."""
import time
from collections import defaultdict

from . import analyze, feeds, inventory, notify, patch
from .util import log, load_state, save_state, append_event, dpkg_cmp, tr

MAX_LLM_CALLS = 10
OSV_EVERY_SEC = 20 * 3600
NOTIFY_OSV = ("CRITICAL", "HIGH")


def _nginx_facts(inv):
    import apt
    c = apt.Cache()
    cand = c["nginx"].candidate.version if "nginx" in c else None
    f = dict(inv["nginx"])
    f["apt_candidate"] = cand
    f["apt_origin"] = ([f"{o.origin}/{o.archive}" for o in c["nginx"].candidate.origins]
                       if cand else [])
    f["note"] = "config_directive_counts = how many times each directive appears in `nginx -T` (0 = not used)"
    return f


def assess_nginx(adv, inv, facts=None):
    st = feeds.nginx_status(adv, inv["nginx"]["version"])
    facts = facts or _nginx_facts(inv)
    rule = {"affected": st == "vulnerable", "official_fix_available": bool(adv["not_vulnerable"]),
            "action": "none" if st != "vulnerable" else "notify", "severity": adv.get("severity", "unknown"),
            "verdict": f"nginx {inv['nginx']['version']}: {st}", "plan": ""}
    res = analyze.assess({"source": "nginx.org security advisory", **adv,
                          "version_check_by_rules": st}, facts, fallback=rule)
    res["rule_status"] = st
    return res


def run_scan(dry_run=False):
    seen = load_state("seen.json")
    first_run = not seen
    for k in ("usn", "nginx", "kev", "osv"):
        seen.setdefault(k, {})
    inv = inventory.collect(full=False)
    dpkg = inv["dpkg"]
    to_notify, want_patch, llm = [], [], [0]

    def can_llm():
        llm[0] += 1
        return llm[0] <= MAX_LLM_CALLS

    # --- Ubuntu USN ---
    try:
        for n in feeds.usn():
            hit = [(name, fixed) for name, fixed, _ in n["packages"]
                   if name in dpkg and dpkg_cmp(dpkg[name]["version"], "lt", fixed)]
            key = n["id"]
            if not hit:
                seen["usn"].setdefault(key, "clean")
                continue
            if seen["usn"].get(key) in ("auto", "notified"):
                continue
            auto = {c[0] for c in patch.candidates(only={h[0] for h in hit})}
            if all(h[0] in auto for h in hit):
                want_patch.append(f"{key}: {', '.join(h[0] for h in hit)}")
                seen["usn"][key] = "auto"
            else:
                to_notify.append(f"• {key} {n['title']} ({', '.join(n['cves'][:3])})\n"
                                 + tr("  уражено: ", "  affected: ")
                                 + ", ".join(f"{a} {dpkg[a]['version']} < {b}" for a, b in hit) + "\n"
                                 + tr("  офіційного фіксу в дозволених репо немає (можливо, лише Ubuntu Pro) — потрібна ручна дія",
                                      "  no official fix in allowed repos (maybe Ubuntu Pro only) — manual action needed"))
                seen["usn"][key] = "notified"
    except Exception as e:  # noqa
        log(f"USN feed failed: {e}")

    # --- nginx.org ---
    if inv["nginx"]["installed"]:
        try:
            facts = None
            for adv in feeds.nginx_advisories():
                key = ",".join(adv["cves"]) + "@" + inv["nginx"]["version"]
                if key in seen["nginx"]:
                    continue
                st = feeds.nginx_status(adv, inv["nginx"]["version"])
                seen["nginx"][key] = st
                if st != "vulnerable":
                    continue
                if not can_llm():
                    continue
                facts = facts or _nginx_facts(inv)
                res = assess_nginx(adv, inv, facts)
                append_event("assessed", {"src": "nginx", "cves": adv["cves"], **res})
                if res["action"] == "auto_patch" or (facts["apt_candidate"] and feeds.nginx_status(
                        adv, facts["apt_candidate"].split("-")[0]) == "fixed"):
                    want_patch.append(f"nginx {', '.join(adv['cves'])}")
                if res["action"] != "none":
                    to_notify.append(f"• nginx {', '.join(adv['cves'])} — {adv['title']} [{adv.get('severity')}]\n"
                                     f"  {res['verdict']}" + (tr("\n  План: ", "\n  Plan: ") + res['plan'] if res.get("plan") else ""))
        except Exception as e:  # noqa
            log(f"nginx feed failed: {e}")

    # --- CISA KEV (actively exploited) ---
    try:
        entries = feeds.kev()
        cutoff = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 30 * 86400))
        fresh = [e for e in entries if e["cveID"] not in seen["kev"]
                 and (not first_run or e.get("dateAdded", "") >= cutoff)]
        for e in entries:
            seen["kev"].setdefault(e["cveID"], e.get("dateAdded"))
        for e, pk in feeds.kev_matches(fresh, dpkg, inv["docker"]):
            dec, facts = ubuntu_decision(e["cveID"], pk, dpkg)
            append_event("kev_match", {"cve": e["cveID"], "pkgs": pk, "decision": dec})
            title = f"🔥 KEV {e['cveID']} {e['vendorProject']} {e['product']} " + tr("(активно експлуатують)", "(actively exploited)")
            if dec == "closed":
                continue
            if dec == "auto":
                want_patch.append(f"KEV {e['cveID']}")
                continue
            if dec == "reboot":
                seen["kev"][e["cveID"]] = "reboot"
                d = facts['decisive']
                to_notify.append(f"• {title}\n" + tr(
                    f"  Фікс уже встановлено ({d['fixed_in']}), але працює старе ядро {d['running_kernel']} — "
                    f"діра відкрита до ребуту. Потрібен ребут сервера.",
                    f"  Fix is installed ({d['fixed_in']}), but the old kernel {d['running_kernel']} is still running — "
                    f"vulnerable until reboot. Server reboot needed."))
                continue
            if not can_llm():
                continue
            res = analyze.assess({"source": "CISA KEV (actively exploited)", **e}, facts)
            append_event("assessed", {"src": "kev", "cve": e["cveID"], **res})
            if res["action"] != "none" and res.get("affected") is not False:
                to_notify.append(f"• {title}\n  {res['verdict']}"
                                 + (tr("\n  План: ", "\n  Plan: ") + res['plan'] if res.get("plan") else ""))
    except Exception as e:  # noqa
        log(f"KEV failed: {e}")

    # --- app dependencies via OSV (daily) ---
    last = load_state("osv_run.json").get("ts", 0)
    if time.time() - last > OSV_EVERY_SEC:
        try:
            to_notify += osv_check(seen, silent=first_run)
            save_state("osv_run.json", {"ts": time.time()})
        except Exception as e:  # noqa
            log(f"OSV failed: {e}")

    save_state("seen.json", seen)

    patched = None
    if want_patch:
        log(f"urgent auto-patch: {want_patch}")
        patched = patch.run_patch(dry_run=dry_run)
    if to_notify:
        notify.send(tr("Знайшов вразливості, що нас стосуються:\n\n", "Found vulnerabilities that affect this host:\n\n") + "\n\n".join(to_notify[:20]),
                    dry_run=dry_run)
    return {"notified": len(to_notify), "patch": patched, "first_run": first_run}


def ubuntu_decision(cve, pkgs, dpkg):
    """Deterministic verdict from Ubuntu CVE tracker.
    closed | auto | reboot | no_fix | unknown (-> ask Claude)."""
    import apt
    cache = apt.Cache()
    facts = {"installed": {}, "apt_candidate": {}, "release": "Ubuntu 24.04"}
    for p in pkgs:
        if p in dpkg:
            facts["installed"][p] = dpkg[p]["version"]
            if p in cache and cache[p].candidate:
                facts["apt_candidate"][p] = {"version": cache[p].candidate.version,
                    "origins": [f"{o.origin}/{o.archive}" for o in cache[p].candidate.origins]}
    tracker = feeds.ubuntu_cve(cve)
    if not tracker or not any(p in dpkg for p in pkgs):
        return "unknown", facts
    decisions = []
    for p in pkgs:
        if p not in dpkg:
            continue
        kernel = p.startswith("linux-image")
        src = "linux" if kernel else dpkg[p]["source"]
        st, fixed = tracker.get(src, (None, ""))
        d = {"package": p, "source": src, "ubuntu_status": st, "fixed_in": fixed}
        if st in ("not-affected", "DNE", "ignored"):
            d["decision"] = "closed"
        elif st == "released" and fixed:
            if kernel:
                run_k = feeds.running_kernel_version()
                inst_k = sorted((k[len("linux-image-"):-len("-generic")] for k in dpkg
                                 if k.startswith("linux-image-") and k.endswith("-generic")
                                 and k[len("linux-image-")].isdigit()),
                                key=__import__("functools").cmp_to_key(
                                    lambda x, y: -1 if dpkg_cmp(x, "lt", y) else (1 if dpkg_cmp(x, "gt", y) else 0)))
                d.update(running_kernel=run_k, newest_installed_kernel=inst_k[-1] if inst_k else None)
                if dpkg_cmp(run_k, "ge", fixed):
                    d["decision"] = "closed"
                elif inst_k and dpkg_cmp(inst_k[-1], "ge", fixed):
                    d["decision"] = "reboot"
                else:
                    d["decision"] = "auto"
            elif dpkg_cmp(dpkg[p]["version"], "ge", fixed):
                d["decision"] = "closed"
            else:
                d["decision"] = "auto" if patch.candidates(only={p}) else "no_fix"
        elif st in ("needed", "pending", "deferred"):
            d["decision"] = "no_fix"
        else:
            d["decision"] = "unknown"
        decisions.append(d)
    facts["decisive"] = decisions[0] if len(decisions) == 1 else decisions
    order = ["reboot", "no_fix", "unknown", "auto", "closed"]
    final = min((d["decision"] for d in decisions), key=order.index, default="unknown")
    if isinstance(facts["decisive"], list):
        facts["decisive"] = next(d for d in decisions if d["decision"] == final) | {"all": decisions}
    return final, facts


def osv_check(seen, silent=False):
    inv = {p: inventory.parse_lockfile(p) for p in inventory.find_lockfiles()}
    where = defaultdict(set)
    for path, deps in inv.items():
        for d in deps:
            where[d].add(inventory.app_name(path))
    hits = feeds.osv_scan(where.keys())
    details = feeds.osv_details({i for ids in hits.values() for i in ids})
    current = {}
    per_app = defaultdict(list)
    for (eco, name, ver), ids in hits.items():
        for vid in ids:
            d = details.get(vid, {})
            sev = d.get("severity", "UNKNOWN")
            for app in where[(eco, name, ver)]:
                key = f"{app}|{name}@{ver}|{vid}"
                current[key] = sev
                if sev in NOTIFY_OSV and key not in seen["osv"]:
                    fix = ", ".join(d.get("fixed", [])[:2]) or tr("немає", "none")
                    per_app[app].append(f"{name}@{ver} {sev} {vid} → " + tr("фікс ", "fix ") + fix)
    save_state("osv_current.json", current)
    for k in current:
        seen["osv"].setdefault(k, time.strftime("%Y-%m-%d"))
    append_event("osv", {"total": len(current),
                         "high_crit": sum(1 for v in current.values() if v in NOTIFY_OSV)})
    if silent or not per_app:
        return []
    out = []
    for app, lines in sorted(per_app.items()):
        out.append(tr(f"• Апка {app} (npm/pip, НЕ оновлюю сам):\n  ", f"• App {app} (npm/pip, NOT auto-updated):\n  ")
                   + "\n  ".join(sorted(set(lines))[:8])
                   + tr("\n  План: гілка security/deps → npm audit fix → білд/тест → PR. Скажи «так» — зроблю.",
                        "\n  Plan: branch security/deps → npm audit fix → build/test → PR."))
    return out
