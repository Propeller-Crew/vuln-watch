"""What is actually installed / running on this host."""
import json
import os
import re

from .util import cfg, run

# nginx directives that change exposure to typical nginx CVEs
NGINX_FEATURES = {
    "http2": r"^\s*(http2\s+on|listen\s[^;]*\bhttp2\b)",
    "http3_quic": r"^\s*(http3\s+on|listen\s[^;]*\bquic\b)",
    "mail_module": r"^\s*mail\s*\{",
    "stream_module": r"^\s*stream\s*\{",
    "ssl_preread": r"^\s*ssl_preread\s+on",
    "resolver": r"^\s*resolver\s",
    "ssi": r"^\s*ssi\s+on",
    "slice": r"^\s*slice\s",
    "aio": r"^\s*aio\s+(on|threads)",
    "proxy_protocol": r"\bproxy_protocol\b",
    "alias": r"^\s*alias\s",
    "try_files": r"^\s*try_files\s",
    "ssl_session_tickets_on": r"^\s*ssl_session_tickets\s+on",
    "ssl_verify_client": r"^\s*ssl_verify_client\s+(on|optional)",
    "map_regex": r"^\s*map\s",
}


def dpkg_packages():
    """{binary_name: {"version":..., "source":...}}"""
    p = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${db:Status-Abbrev}\n"])
    out = {}
    for line in p.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not parts[3].startswith("ii"):
            continue
        out[parts[0]] = {"version": parts[1], "source": parts[2] or parts[0]}
    return out


def nginx_dump():
    p = run(["nginx", "-T"])
    return p.stdout if p.returncode == 0 else ""


def nginx_facts(dump=None):
    dump = dump if dump is not None else nginx_dump()
    v = run(["nginx", "-V"])
    text = v.stderr + v.stdout
    m = re.search(r"nginx/(\S+)", text)
    facts = {"installed": bool(text.strip()), "version": m.group(1) if m else None,
             "compiled_modules": sorted(set(re.findall(r"--with-([a-z0-9_]+_module)", text)))}
    uses = {}
    for k, rx in NGINX_FEATURES.items():
        uses[k] = len(re.findall(rx, dump, re.M))
    facts["config_directive_counts"] = uses
    facts["vhosts"] = len(server_names(dump))
    return facts


def server_names(dump=None):
    """[(name, has_ssl)] from nginx -T."""
    dump = dump if dump is not None else nginx_dump()
    names = {}
    # crude server-block walk: track listen ssl within each server{}
    blocks = re.split(r"^\s*server\s*\{", dump, flags=re.M)[1:]
    for b in blocks:
        ssl = bool(re.search(r"^\s*listen\s[^;]*\b(443|ssl)\b", b, re.M))
        for m in re.finditer(r"^\s*server_name\s+([^;]+);", b, re.M):
            for n in m.group(1).split():
                if n in ("_", "localhost") or "*" in n or n.startswith("~"):
                    continue
                names[n] = names.get(n, False) or ssl
    return sorted(names.items())


def docker_images():
    p = run(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}"])
    if p.returncode != 0:
        return []
    return [dict(zip(("name", "image"), l.split("\t"))) for l in p.stdout.splitlines() if l]


def runtimes():
    out = {}
    for name, cmd in (("node", ["node", "--version"]), ("python3", ["python3", "--version"])):
        try:
            p = run(cmd)
            out[name] = (p.stdout or p.stderr).strip().lstrip("v").replace("Python ", "")
        except FileNotFoundError:
            pass
    return out


def find_lockfiles():
    inv = cfg()["inventory"]
    found = []
    skip = {"node_modules", ".git", ".next", "dist", "build", ".venv", "venv"}
    for root in inv["lockfile_roots"]:
        base = root.rstrip("/").count("/")
        for dirpath, dirs, files in os.walk(root):
            depth = dirpath.count("/") - base
            dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")] \
                if depth < inv["lockfile_max_depth"] else []
            for f in files:
                if f in ("package-lock.json", "requirements.txt"):
                    found.append(os.path.join(dirpath, f))
    return sorted(found)


def parse_lockfile(path):
    """[(ecosystem, name, version)] — production deps only."""
    out = []
    try:
        if path.endswith("package-lock.json"):
            with open(path) as f:
                data = json.load(f)
            for key, meta in (data.get("packages") or {}).items():
                if not key or meta.get("dev") or meta.get("link") or "version" not in meta:
                    continue
                name = meta.get("name") or key.split("node_modules/")[-1]
                out.append(("npm", name, meta["version"]))
            if not data.get("packages"):  # lockfile v1
                def walk(deps):
                    for n, m in (deps or {}).items():
                        if not m.get("dev") and "version" in m:
                            out.append(("npm", n, m["version"]))
                        walk(m.get("dependencies"))
                walk(data.get("dependencies"))
        elif path.endswith("requirements.txt"):
            with open(path) as f:
                for line in f:
                    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([^\s;#]+)", line)
                    if m:
                        out.append(("PyPI", m.group(1), m.group(3)))
    except (OSError, ValueError):
        pass
    return sorted(set(out))


def app_name(lockfile):
    parts = lockfile.split("/")
    # /opt/<app>/... or /home/<u>/<app>/...
    if parts[1] == "opt" and len(parts) > 3:
        return "/".join(p for p in parts[2:-1] if p not in ("app", "web", "server", "site"))[:60] or parts[2]
    return "/".join(parts[1:-1])


def collect(full=True):
    inv = {"dpkg": dpkg_packages(), "runtimes": runtimes(), "docker": docker_images()}
    inv["nginx"] = nginx_facts()
    if full:
        inv["lockfiles"] = {p: parse_lockfile(p) for p in find_lockfiles()}
    return inv
