"""Discover service config file locations by pattern-matching appdata directories.

Walks each directory in search_dirs up to MAX_DEPTH levels, matches directory
names against the patterns defined in app_signatures.APP_SIGNATURES, and
returns the absolute path to the config file when found.

Also provides scan_remote_service_configs() for SSH-based remote scanning.
"""

import fnmatch
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Optional

from src.app_signatures import APP_SIGNATURES

MAX_DEPTH = 5

# Directories that will never contain service appdata — skip them entirely
_PRUNE = {
    "proc", "sys", "dev", "run", "tmp", "boot", "snap",
    "lost+found", "node_modules", "__pycache__", ".git",
    "logs", "log", "cache", "Cache", "Backups", "backup",
    "MediaCover", "metadata", "media", "transcodes", "thumbnails",
    "tv", "movies", "music", "photos", "downloads",
}

# Remote scan script — executed on the remote host via "python3 -c <script>".
# Must contain NO literal single-quote characters (shlex.quote wraps in single quotes).
# Use chr(39) where a single-quote character is needed at runtime.
_REMOTE_SCAN_PY = """\
import sys, json, os, fnmatch, re, configparser
from pathlib import Path

cfg = json.loads(sys.stdin.read())
sigs = cfg["sigs"]
search_dirs = cfg["search_dirs"]
prune = set(cfg["prune"])
MAX_DEPTH = 5
found = {}

for base in search_dirs:
    base_path = Path(base)
    if not base_path.is_dir():
        continue
    base_depth = len(base_path.parts)
    for root_str, dirs, files in os.walk(base, followlinks=False):
        root = Path(root_str)
        depth = len(root.parts) - base_depth
        dirs[:] = [d for d in dirs if d not in prune and not d.startswith(".")]
        if depth >= MAX_DEPTH:
            dirs[:] = []
            continue
        dirname = root.name.lower()
        for sid, sig in sigs.items():
            if sid in found:
                continue
            for pattern in sig.get("dir_patterns", []):
                if fnmatch.fnmatch(dirname, pattern.lower()):
                    candidates = sig.get("config_file_candidates") or [sig.get("config_file", "")]
                    for candidate in candidates:
                        if not candidate:
                            continue
                        cpath = root / candidate
                        if not cpath.exists():
                            continue
                        value = None
                        fmt = sig.get("format", "")
                        try:
                            text = cpath.read_text(errors="ignore")
                            if fmt == "ini":
                                cp2 = configparser.ConfigParser()
                                cp2.read_string(text)
                                sect = sig.get("ini_section", "")
                                ikey = sig.get("ini_key", "")
                                if cp2.has_option(sect, ikey):
                                    value = cp2.get(sect, ikey).strip()
                            elif fmt == "json":
                                obj = json.loads(text)
                                for k in sig.get("json_path", []):
                                    obj = obj.get(k) if isinstance(obj, dict) else None
                                if isinstance(obj, str):
                                    value = obj
                            elif fmt == "yaml":
                                try:
                                    import yaml as _y
                                    obj = _y.safe_load(text)
                                    for k in sig.get("yaml_path", []):
                                        obj = obj.get(k) if isinstance(obj, dict) else None
                                    if isinstance(obj, str):
                                        value = obj
                                except ImportError:
                                    pass
                            elif fmt == "toml":
                                tkey = sig.get("toml_key", "")
                                m = re.search(r"^" + re.escape(tkey) + r"\\s*=\\s*(.+)$", text, re.MULTILINE)
                                if m:
                                    value = m.group(1).strip().strip(chr(34)).strip(chr(39))
                            elif fmt == "env":
                                ekey = sig.get("env_key", "")
                                m = re.search(r"^" + re.escape(ekey) + r"\\s*=\\s*(.+)$", text, re.MULTILINE)
                                if m:
                                    value = m.group(1).strip().strip(chr(34)).strip(chr(39))
                        except Exception:
                            pass
                        found[sid] = {"path": str(cpath), "value": value}
                        break
                    break

print(json.dumps(found))
"""


def detect_service_paths(search_dirs: list[str]) -> dict[str, str]:
    """Return {service_id: absolute_config_path} for every detected service."""
    found: dict[str, str] = {}

    for base in search_dirs:
        base_path = Path(base)
        if not base_path.is_dir():
            continue

        base_depth = len(base_path.parts)

        for root_str, dirs, _files in os.walk(base_path, followlinks=False):
            root = Path(root_str)
            depth = len(root.parts) - base_depth

            # Prune directories we should never descend into
            dirs[:] = [
                d for d in dirs
                if d not in _PRUNE and not d.startswith(".")
            ]

            if depth >= MAX_DEPTH:
                dirs[:] = []  # stop descending
                continue

            # Check if this directory matches any service signature
            dirname = root.name.lower()
            for sid, sig in APP_SIGNATURES.items():
                if sid in found:
                    continue
                for pattern in sig["dir_patterns"]:
                    if fnmatch.fnmatch(dirname, pattern.lower()):
                        candidates = (
                            sig.get("config_file_candidates")
                            or [sig.get("config_file", "")]
                        )
                        for candidate in candidates:
                            if not candidate:
                                continue
                            config_path = root / candidate
                            if config_path.exists():
                                found[sid] = str(config_path)
                                break
                        break  # stop trying patterns for this service

    return found


def scan_remote_service_configs(
    host: str,
    user: str,
    search_dirs: list[str],
    key_path: Optional[str] = None,
) -> dict[str, dict]:
    """Scan a remote host for service config files and key values via SSH.

    Returns {service_id: {"path": str, "value": Optional[str]}}.
    The detection script is passed via -c; JSON config is sent via stdin.
    """
    _SAFE_FIELDS = {
        "dir_patterns", "config_file", "config_file_candidates",
        "format", "ini_section", "ini_key", "json_path",
        "yaml_path", "toml_key", "env_key",
    }
    sigs_dict: dict[str, dict] = {
        sid: {k: v for k, v in sig.items() if k in _SAFE_FIELDS}
        for sid, sig in APP_SIGNATURES.items()
    }

    stdin_data = json.dumps({
        "sigs": sigs_dict,
        "search_dirs": search_dirs,
        "prune": list(_PRUNE),
    })

    ssh_cmd = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
    ]
    if key_path:
        ssh_cmd += ["-i", key_path]
    ssh_cmd += [f"{user}@{host}", f"python3 -c {shlex.quote(_REMOTE_SCAN_PY)}"]

    try:
        result = subprocess.run(
            ssh_cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {}
    except Exception:
        return {}

    if result.returncode != 0:
        return {}

    try:
        return json.loads(result.stdout.strip())
    except Exception:
        return {}
