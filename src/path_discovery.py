"""Discover service config file locations by pattern-matching appdata directories.

Walks each directory in search_dirs up to MAX_DEPTH levels, matches directory
names against the patterns defined in app_signatures.APP_SIGNATURES, and
returns the absolute path to the config file when found.

Also provides scan_remote_service_configs() for SSH-based remote scanning.
"""

import fnmatch
import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Optional

from src.app_signatures import APP_SIGNATURES

MAX_DEPTH = 8

# Directories that will never contain service appdata — skip them entirely
_PRUNE = {
    "proc", "sys", "dev", "run", "tmp", "boot", "snap",
    "lost+found", "node_modules", "__pycache__", ".git",
    "logs", "log", "cache", "Cache", "Backups", "backup",
    "MediaCover", "metadata", "media", "transcodes", "thumbnails",
    "tv", "movies", "music", "photos", "downloads",
}

# Suffixes/names that identify backup copies — skip so live configs win.
_BACKUP_KEYWORDS = frozenset({"backup", "bak", "old", "config-backup"})


def _is_backup_dir(name: str) -> bool:
    """Return True if a directory name looks like a backup copy."""
    lo = name.lower()
    return lo in _BACKUP_KEYWORDS or any(
        lo.endswith(f"-{kw}") or lo.endswith(f"_{kw}") or lo.endswith(f".{kw}")
        for kw in _BACKUP_KEYWORDS
    )

# Remote scan script — executed on the remote host via "python3 -c <script>".
# Must contain NO literal single-quote characters (shlex.quote wraps in single quotes).
# Use chr(39) where a single-quote character is needed at runtime.
_REMOTE_SCAN_PY = """\
import sys, json, os, fnmatch, re, configparser
import xml.etree.ElementTree as ET
from pathlib import Path

cfg = json.loads(sys.stdin.read())
sigs = cfg["sigs"]
search_dirs = cfg["search_dirs"]
prune = set(cfg["prune"])
MAX_DEPTH = 8
found = {}
_BAK_KW = frozenset(["backup", "bak", "old", "config-backup"])
def _is_bak(n):
    lo = n.lower()
    return lo in _BAK_KW or any(lo.endswith("-" + k) or lo.endswith("_" + k) or lo.endswith("." + k) for k in _BAK_KW)

for base in search_dirs:
    base_path = Path(base)
    if not base_path.is_dir():
        continue
    base_depth = len(base_path.parts)
    for root_str, dirs, files in os.walk(base, followlinks=False):
        root = Path(root_str)
        depth = len(root.parts) - base_depth
        dirs[:] = [d for d in dirs if d not in prune and not d.startswith(".") and not _is_bak(d)]
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
                                        if isinstance(obj, dict):
                                            obj = obj.get(k)
                                        elif isinstance(obj, list) and isinstance(k, int):
                                            obj = obj[k] if k < len(obj) else None
                                        else:
                                            obj = None
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
                            elif fmt == "arr_xml":
                                root_el = ET.fromstring(text)
                                el = root_el.find("ApiKey")
                                if el is not None and el.text:
                                    value = el.text.strip()
                            elif fmt == "xml_tag":
                                xtag = sig.get("xml_tag", "ApiKey")
                                root_el = ET.fromstring(text)
                                el = root_el.find(f".//{xtag}")
                                if el is not None and el.text:
                                    value = el.text.strip()
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

            # Prune directories we should never descend into, including backup copies
            dirs[:] = [
                d for d in dirs
                if d not in _PRUNE and not d.startswith(".") and not _is_backup_dir(d)
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
        "yaml_path", "toml_key", "env_key", "xml_tag",
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

    import logging as _log
    _logger = _log.getLogger(__name__)

    ssh_cmd = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
    ]
    if key_path:
        ssh_cmd += ["-i", key_path]
    # Prepend common paths so python3 is found even in minimal non-login shells
    # (TrueNAS Scale, NixOS, and some other distros omit /usr/bin from SSH PATH).
    inner = f"python3 -c {shlex.quote(_REMOTE_SCAN_PY)}"
    ssh_cmd += [
        f"{user}@{host}",
        f"PATH=/usr/local/bin:/usr/bin:/bin:$PATH {inner}",
    ]

    try:
        result = subprocess.run(
            ssh_cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        _logger.warning("remote scan of %s@%s timed out", user, host)
        return {}
    except Exception as exc:
        _logger.warning("remote scan of %s@%s failed: %s", user, host, exc)
        return {}

    if result.returncode != 0:
        _logger.warning(
            "remote scan of %s@%s exited %d: %s",
            user, host, result.returncode, result.stderr.strip()[:300],
        )
        return {}

    try:
        return json.loads(result.stdout.strip())
    except Exception as exc:
        _logger.warning(
            "remote scan of %s@%s: could not parse output: %s | stdout[:200]=%r",
            user, host, exc, result.stdout[:200],
        )
        return {}


# ---------------------------------------------------------------------------
# Local config value parser — mirrors the _REMOTE_SCAN_PY format dispatch
# ---------------------------------------------------------------------------

def parse_value_from_config(config_path: str, service_id: str) -> Optional[str]:
    """Read the current key value for a service from its detected config file.

    Returns None if the file is missing, the service has no APP_SIGNATURES entry,
    or parsing fails for any reason.
    """
    import configparser as _cp
    import xml.etree.ElementTree as _ET

    path = Path(config_path)
    if not path.exists():
        return None
    sig = APP_SIGNATURES.get(service_id)
    if not sig:
        return None
    fmt = sig.get("format", "")
    try:
        text = path.read_text(errors="ignore")
        if fmt == "arr_xml":
            root_el = _ET.fromstring(text)
            el = root_el.find("ApiKey")
            return el.text.strip() if el is not None and el.text else None
        if fmt == "xml_tag":
            xtag = sig.get("xml_tag", "ApiKey")
            root_el = _ET.fromstring(text)
            el = root_el.find(f".//{xtag}")
            return el.text.strip() if el is not None and el.text else None
        if fmt == "ini":
            cp = _cp.ConfigParser()
            cp.read_string(text)
            sect = sig.get("ini_section", "")
            ikey = sig.get("ini_key", "")
            return cp.get(sect, ikey).strip() if cp.has_option(sect, ikey) else None
        if fmt == "json":
            obj = json.loads(text)
            for k in sig.get("json_path", []):
                obj = obj.get(k) if isinstance(obj, dict) else None
            return obj if isinstance(obj, str) else None
        if fmt == "yaml":
            try:
                import yaml as _y
                obj = _y.safe_load(text)
                for k in sig.get("yaml_path", []):
                    if isinstance(obj, dict):
                        obj = obj.get(k)
                    elif isinstance(obj, list) and isinstance(k, int):
                        obj = obj[k] if k < len(obj) else None
                    else:
                        obj = None
                return obj if isinstance(obj, str) else None
            except ImportError:
                return None
        if fmt == "toml":
            tkey = sig.get("toml_key", "")
            m = re.search(r"^" + re.escape(tkey) + r"\s*=\s*(.+)$", text, re.MULTILINE)
            return m.group(1).strip().strip("'\"") if m else None
        if fmt == "env":
            ekey = sig.get("env_key", "")
            m = re.search(r"^" + re.escape(ekey) + r"\s*=\s*(.+)$", text, re.MULTILINE)
            return m.group(1).strip().strip("'\"") if m else None
    except Exception as exc:
        import logging as _l
        _l.getLogger(__name__).warning(
            "parse_value_from_config(%s, %s): %s", config_path, service_id, exc
        )
    return None


_NEEDS_QUOTING = re.compile(r"[^\w@%+=:,./-]")


def _shell_quote_value(v: str) -> str:
    """Quote a value for safe inclusion in a shell-sourceable env file."""
    if not _NEEDS_QUOTING.search(v):
        return v
    return "'" + v.replace("'", "'\\''") + "'"


def export_secrets_env(db_path: str, output_path: str) -> int:
    """Write a shell-sourceable secrets.env file from detected service config files.

    Reads every services row that has both env_var and detected_config_path set,
    parses the current value from the config file on disk, and writes lines of the
    form ``ENV_VAR=value`` (single-quoted when the value contains special chars),
    sorted alphabetically by env_var.

    The write is atomic: content goes to ``output_path + ".tmp"``, fsynced, then
    renamed into place.  Permissions are set to 0o644.

    Returns the number of entries written.  Per-service errors are logged and
    skipped; failures never propagate to callers (always returns 0 on DB error).
    """
    import logging as _log
    import sqlite3 as _sql

    _logger = _log.getLogger(__name__)
    try:
        con = _sql.connect(db_path, timeout=10)
        try:
            rows = con.execute(
                "SELECT id, env_var, detected_config_path "
                "FROM services "
                "WHERE env_var IS NOT NULL AND detected_config_path IS NOT NULL"
            ).fetchall()
        finally:
            con.close()
    except Exception as exc:
        _logger.warning("export_secrets_env: cannot read DB %s: %s", db_path, exc)
        return 0

    lines: list[str] = []
    for service_id, env_var, config_path in sorted(rows, key=lambda r: r[1]):
        try:
            val = parse_value_from_config(config_path, service_id)
            if val and len(val) >= 8:
                lines.append(f"{env_var}={_shell_quote_value(val)}")
        except Exception as exc:
            _logger.warning(
                "export_secrets_env: skipping %s (%s): %s", service_id, env_var, exc
            )

    if not lines:
        _logger.info("export_secrets_env: no values to export from %s", db_path)
        return 0

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(out) + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        tmp.chmod(0o600)
        os.replace(str(tmp), str(out))
        _logger.info("export_secrets_env: wrote %d entries to %s", len(lines), output_path)
        return len(lines)
    except Exception as exc:
        _logger.warning("export_secrets_env: write to %s failed: %s", output_path, exc)
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        return 0
