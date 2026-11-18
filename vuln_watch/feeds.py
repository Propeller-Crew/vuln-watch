"""Free vulnerability sources: Ubuntu USN, nginx.org advisories, CISA KEV, OSV.dev."""
import html
import json
import re

from .util import http_get, log, cfg, load_state, save_state, dpkg_cmp


def usn(pages=3):
    """Latest Ubuntu Security Notices for our release (API max limit=20)."""
    rel = cfg()["release"]
    notices = []
    for i in range(pages):
        d = http_get(f"https://ubuntu.com/security/notices.json?limit=20&offset={i * 20}&release={rel}",
                     as_json=True)
        notices += d.get("notices", [])
    out = []
    for n in notices:
        pk = [(p["name"], p["version"], p.get("pocket"))
              for p in n.get("release_packages", {}).get(rel, []) if not p.get("is_source")]
        out.append({"id": n["id"], "title": n["title"], "summary": n.get("summary", ""),
                    "cves": n.get("cves_ids", []), "published": n.get("published"),
                    "packages": pk})
    return out


def nginx_advisories():
    page = http_get("https://nginx.org/en/security_advisories.html")
    out = []
    for li in re.findall(r"<li><p>(.*?)</p></li>", page, re.S):
        parts = [html.unescape(re.sub(r"<[^>]+>", "", x)).strip() for x in re.split(r"<br\s*/?>", li)]
        item = {"title": parts[0], "cves": [], "not_vulnerable": [], "vulnerable": []}
        for p in parts[1:]:
            if p.lower().startswith("severity"):
                item["severity"] = p.split(":", 1)[1].strip()
            elif p.lower().startswith("not vulnerable"):
                item["not_vulnerable"] = [x.strip() for x in p.split(":", 1)[1].split(",") if x.strip()]
            elif p.lower().startswith("vulnerable"):
                item["vulnerable"] = [x.strip() for x in p.split(":", 1)[1].split(",") if x.strip()]
            elif "CVE-" in p:
                item["cves"] += ["CVE-" + c for c in re.findall(r"CVE-(?:CVE-)?(\d{4}-\d+)", p)]
        out.append(item)
    return out


def _minor(v):
    m = re.match(r"(\d+)\.(\d+)", v)
    return m.groups() if m else None


def nginx_status(adv, version):
    """'fixed' | 'vulnerable' | 'not-affected' for an installed upstream version."""
    if not version:
        return "not-affected"
    fixes = [x.rstrip("+") for x in adv["not_vulnerable"] if x.endswith("+")]
    for f in fixes:
        if _minor(f) == _minor(version) and dpkg_cmp(version, "ge", f):
            return "fixed"
    if fixes and all(dpkg_cmp(version, "ge", f) for f in fixes):
        return "fixed"
    for r in adv["vulnerable"]:
        if "-" in r:
            lo, hi = r.split("-", 1)
            if dpkg_cmp(version, "ge", lo) and dpkg_cmp(version, "le", hi):
                return "vulnerable"
    return "not-affected"


def ubuntu_cve(cve):
    """{source_pkg: (status, fixed_version)} for our release from Ubuntu CVE tracker."""
    rel = cfg()["release"]
    try:
        d = http_get(f"https://ubuntu.com/security/cves/{cve}.json", as_json=True)
    except Exception as e:  # noqa
        log(f"ubuntu cve {cve}: {e}")
        return None
    out = {"_priority": d.get("priority")}
    for p in d.get("packages", []):
        for st in p.get("statuses", []):
            if st.get("release_codename") == rel:
                out[p["name"]] = (st.get("status"), st.get("description") or "")
    return out


def running_kernel_version():
    """'6.8.0-90-generic' -> '6.8.0-90'"""
    import os
    return re.sub(r"-[a-z]+$", "", os.uname().release)


def kev():
    urls = ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"]
    for u in urls:
        try:
            return http_get(u, as_json=True, timeout=90).get("vulnerabilities", [])
        except Exception as e:  # noqa
            log(f"KEV {u.split('/')[2]}: {e}")
    return []


# KEV product -> dpkg package names that represent it on Ubuntu
KEV_ALIASES = {
    "kernel": ["linux-image-generic", "linux-image-virtual"],
    "linux kernel": ["linux-image-generic", "linux-image-virtual"],
    "openssh": ["openssh-server"], "node.js": ["nodejs"], "chromium": ["google-chrome-stable"],
    "chrome": ["google-chrome-stable"], "docker": ["docker-ce"], "docker desktop": [],
    "glibc": ["libc6"], "gnu c library": ["libc6"], "openssl": ["openssl", "libssl3t64", "libssl3"],
    "sudo": ["sudo"], "polkit": ["polkitd", "policykit-1"], "xz": ["xz-utils"],
    "nginx": ["nginx"], "redis": ["redis-server"], "postgresql": ["postgresql"],
    "tailscale": ["tailscale"], "cups": ["cups"], "exim": ["exim4-base"], "samba": ["samba"],
}


def kev_matches(entries, dpkg, docker_images):
    images = " ".join(d["image"].lower() for d in docker_images)
    out = []
    for e in entries:
        prod = e.get("product", "").lower().strip()
        vendor = e.get("vendorProject", "").lower().strip()
        names = KEV_ALIASES.get(prod, KEV_ALIASES.get(f"{vendor} {prod}"))
        if names is None:
            names = [prod.replace(" ", "-")]
        hit = [n for n in names if n in dpkg]
        if not hit and len(prod) > 3 and re.search(rf"\b{re.escape(prod)}\b", images):
            hit = [f"docker:{prod}"]
        if hit:
            out.append((e, hit))
    return out


def osv_scan(pkgs):
    """pkgs: iterable of (ecosystem, name, version) -> {(eco,name,ver): [vuln_ids]}"""
    pkgs = sorted(set(pkgs))
    res = {}
    for i in range(0, len(pkgs), 1000):
        chunk = pkgs[i:i + 1000]
        body = json.dumps({"queries": [{"package": {"ecosystem": e, "name": n}, "version": v}
                                       for e, n, v in chunk]}).encode()
        d = http_get("https://api.osv.dev/v1/querybatch", as_json=True, data=body, timeout=120)
        for key, r in zip(chunk, d.get("results", [])):
            ids = [v["id"] for v in r.get("vulns", [])]
            if ids:
                res[key] = ids
    return res


def osv_details(ids):
    cache = load_state("osv_cache.json")
    for vid in ids:
        if vid in cache:
            continue
        try:
            v = http_get(f"https://api.osv.dev/v1/vulns/{vid}", as_json=True)
        except Exception as e:  # noqa
            log(f"osv {vid}: {e}")
            continue
        sev = (v.get("database_specific") or {}).get("severity") or "UNKNOWN"
        fixed = sorted({ev["fixed"] for a in v.get("affected", []) for r in a.get("ranges", [])
                        for ev in r.get("events", []) if "fixed" in ev})
        cache[vid] = {"summary": (v.get("summary") or "")[:200], "severity": sev.upper(),
                      "aliases": v.get("aliases", []), "fixed": fixed[:6]}
    save_state("osv_cache.json", cache)
    return cache
