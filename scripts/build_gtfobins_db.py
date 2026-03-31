#!/usr/bin/env python3
"""
Build database/gtfobins.json and database/gtfobins_flat.db from upstream GTFOBins.
Source: https://gtfobins.org/ (content from https://github.com/GTFOBins/GTFOBins.github.io)

Requires: PyYAML (python3 -m pip install pyyaml)
Run from repo root: python3 scripts/build_gtfobins_db.py
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("[ERROR] Install PyYAML: python3 -m pip install pyyaml", file=sys.stderr)
    sys.exit(1)

GITHUB_API = "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/contents/_gtfobins"
RAW_BASE = "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins"
USER_AGENT = "linuxpi-gtfobins-build/1.0"

# Prefer these function types first when many exist (most relevant to LinuxPi / privesc).
FUNC_PRIORITY = [
    "shell",
    "privilege-escalation",
    "command",
    "reverse-shell",
    "bind-shell",
    "file-write",
    "file-read",
    "upload",
    "download",
    "library-load",
    "inherit",
    "sudo",
    "capabilities",
]

MAX_PER_CONTEXT = 8


def _http_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def _http_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def list_gtfo_files() -> list[str]:
    names: list[str] = []
    page = 1
    while True:
        url = f"{GITHUB_API}?per_page=100&page={page}"
        chunk = _http_json(url)
        if not chunk:
            break
        for item in chunk:
            if item.get("type") != "file":
                continue
            n = item["name"]
            if n in ("README.md",):
                continue
            names.append(n)
        if len(chunk) < 100:
            break
        page += 1
    return sorted(names)


def load_yaml_entry(name: str) -> dict[str, Any]:
    raw = _http_text(f"{RAW_BASE}/{name}")
    if raw.startswith("---"):
        parts = raw.split("---", 2)
        body = parts[-1] if len(parts) > 2 else raw
    else:
        body = raw
    data = yaml.safe_load(body)
    return data if isinstance(data, dict) else {}


def resolve_code(variant: dict[str, Any], ctx: str) -> str | None:
    ctxs = variant.get("contexts") or {}
    if ctx not in ctxs:
        return None
    node = ctxs[ctx]
    if isinstance(node, dict) and node.get("code"):
        return str(node["code"]).strip()
    base = (variant.get("code") or "").strip()
    if not base:
        return None
    line = base.split("\n")[0].strip()
    if ctx == "sudo":
        if line.startswith("sudo "):
            return line
        return f"sudo {line}"
    if ctx == "suid":
        parts = line.split(None, 1)
        if parts and not parts[0].startswith(("/", "./")):
            return f"./{parts[0]}" + (f" {parts[1]}" if len(parts) > 1 else "")
        return line
    if ctx == "capabilities":
        return line
    return None


def func_sort_key(name: str) -> int:
    n = name.replace("_", "-")
    try:
        return FUNC_PRIORITY.index(n)
    except ValueError:
        return len(FUNC_PRIORITY) + hash(n) % 100


def extract_contexts(entry: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = defaultdict(list)
    funcs = entry.get("functions") or {}
    if not isinstance(funcs, dict):
        return out

    seen_cmd: dict[str, set[str]] = defaultdict(set)

    for func_name, variants in funcs.items():
        if not isinstance(variants, list):
            continue
        ftype = str(func_name).replace("_", "-")
        for var in variants:
            if not isinstance(var, dict):
                continue
            note = var.get("comment")
            if note and isinstance(note, str):
                note = " ".join(note.split())[:240]
            else:
                note = ""
            for ctx in ("sudo", "suid", "capabilities"):
                code = resolve_code(var, ctx)
                if not code:
                    continue
                cmd = " ".join(code.split())
                if cmd in seen_cmd[ctx]:
                    continue
                seen_cmd[ctx].add(cmd)
                item: dict[str, str] = {"type": ftype, "command": cmd}
                if note:
                    item["note"] = note
                out[ctx].append(item)

    for ctx in list(out.keys()):
        out[ctx].sort(key=lambda x: (func_sort_key(x["type"]), x["command"][:40]))
        out[ctx] = out[ctx][:MAX_PER_CONTEXT]
    return out


def apply_aliases(
    binaries: dict[str, dict[str, list[dict[str, str]]]],
    alias_map: dict[str, str],
) -> None:
    for alias, target in alias_map.items():
        if target in binaries and alias not in binaries:
            binaries[alias] = json.loads(json.dumps(binaries[target]))


def load_local_dir(gtfo_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    raw_entries: dict[str, dict[str, Any]] = {}
    alias_map: dict[str, str] = {}
    for path in sorted(gtfo_dir.iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"[WARN] Skip {path.name}: {e}", file=sys.stderr)
            continue
        if raw.startswith("---"):
            parts = raw.split("---", 2)
            body = parts[-1] if len(parts) > 2 else raw
        else:
            body = raw
        try:
            entry = yaml.safe_load(body)
        except yaml.YAMLError as e:
            print(f"[WARN] YAML {path.name}: {e}", file=sys.stderr)
            continue
        if not isinstance(entry, dict):
            continue
        name = path.name
        if entry.get("alias"):
            alias_map[name] = str(entry["alias"]).strip()
            continue
        if not entry.get("functions"):
            continue
        raw_entries[name] = entry
    return raw_entries, alias_map


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    db_dir = root / "database"
    db_dir.mkdir(parents=True, exist_ok=True)
    json_path = db_dir / "gtfobins.json"
    flat_path = db_dir / "gtfobins_flat.db"

    local_arg = None
    argv = [a for a in sys.argv[1:] if a != "--"]
    if len(argv) >= 2 and argv[0] == "--local":
        local_arg = Path(argv[1]).expanduser().resolve()

    raw_entries: dict[str, dict[str, Any]] = {}
    alias_map: dict[str, str] = {}

    if local_arg:
        if not local_arg.is_dir():
            print(f"[ERROR] Not a directory: {local_arg}", file=sys.stderr)
            return 1
        print(f"[*] Loading GTFOBins YAML from {local_arg}…")
        raw_entries, alias_map = load_local_dir(local_arg)
        print(f"[*] Parsed {len(raw_entries)} entries, {len(alias_map)} aliases")
    else:
        print("[*] Listing GTFOBins entries from GitHub…")
        try:
            names = list_gtfo_files()
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
            print(f"[ERROR] Network/API: {e}", file=sys.stderr)
            print(
                "      Clone upstream and use: python3 scripts/build_gtfobins_db.py --local /path/to/GTFOBins.github.io/_gtfobins",
                file=sys.stderr,
            )
            return 1

        print(f"[*] Fetching {len(names)} YAML files…")
        for i, name in enumerate(names):
            try:
                entry = load_yaml_entry(name)
            except (urllib.error.URLError, OSError, yaml.YAMLError) as e:
                print(f"[WARN] Skip {name}: {e}", file=sys.stderr)
                continue
            if entry.get("alias"):
                alias_map[name] = str(entry["alias"]).strip()
                continue
            if not entry.get("functions"):
                continue
            raw_entries[name] = entry
            if (i + 1) % 50 == 0:
                print(f"    … {i + 1}/{len(names)}")

    binaries: dict[str, dict[str, list[dict[str, str]]]] = {}
    for name, entry in raw_entries.items():
        ctxs = extract_contexts(entry)
        if any(ctxs.values()):
            binaries[name] = {
                "sudo": ctxs.get("sudo", []),
                "suid": ctxs.get("suid", []),
                "capabilities": ctxs.get("capabilities", []),
            }

    apply_aliases(binaries, alias_map)

    # Common binary name aliases on Linux distros
    if "python" in binaries and "python3" not in binaries:
        binaries["python3"] = json.loads(json.dumps(binaries["python"]))
    if "php" in binaries and "php8.2" not in binaries:
        pass  # optional: skip distro-specific

    meta = {
        "version": "2.0.0",
        "source": "https://gtfobins.org/ (GTFOBins.github.io _gtfobins YAML)",
        "last_updated": __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .strftime("%Y-%m-%d"),
        "entry_count": len(binaries),
    }

    payload = {"_metadata": meta, "binaries": binaries}

    print(f"[+] Writing {json_path} ({len(binaries)} binaries)")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")

    flat_lines = [
        "# gtfobins_flat.db - Auto-generated from GTFOBins (https://gtfobins.org/)",
        "# Format: binary|context|type|command",
    ]
    for bin_name in sorted(binaries.keys()):
        b = binaries[bin_name]
        for ctx in ("sudo", "suid", "capabilities"):
            for item in b.get(ctx, []):
                bname = bin_name.replace("|", "")
                ctype = item["type"].replace("|", "/")
                cmd = item["command"].replace("|", " ").replace("\n", " ")
                flat_lines.append(f"{bname}|{ctx}|{ctype}|{cmd}")

    with open(flat_path, "w", encoding="utf-8") as f:
        f.write("\n".join(flat_lines) + "\n")

    print(f"[+] Wrote {flat_path} ({len(flat_lines) - 2} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
