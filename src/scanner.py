"""Filesystem and database scanning for secret references."""

import hashlib
import logging
import itertools
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.services_registry import load_rotate_keys_config

logger = logging.getLogger("verificationrotation")

# ---------------------------------------------------------------------------
# Boundary-safe regex
# ---------------------------------------------------------------------------
_BOUNDARY = r'(?<![A-Za-z0-9_\-./]){}(?![A-Za-z0-9_\-./])'

# Allowed characters for SQL identifiers (table/column names) used in db_refs.
# Prevents SQL injection from user-controlled host db_refs configurations.
_SAFE_SQL_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def _validate_db_ref(db_path: str, table: str, column: str) -> tuple[str, str, str]:
    """Validate a db_ref tuple, raising ValueError on unsafe identifiers."""
    if not _SAFE_SQL_IDENTIFIER.match(table):
        raise ValueError(f"Invalid SQL table name in db_refs: {table!r}")
    if not _SAFE_SQL_IDENTIFIER.match(column):
        raise ValueError(f"Invalid SQL column name in db_refs: {column!r}")
    return (db_path, table, column)


def _key_pattern(key: str) -> re.Pattern:
    return re.compile(_BOUNDARY.format(re.escape(key)))


def _key_matches(key: str, text: str) -> bool:
    return bool(_key_pattern(key).search(text))


def _key_replace(old: str, new: str, text: str) -> str:
    return _key_pattern(old).sub(lambda _: new, text)


# ---------------------------------------------------------------------------
# File skip logic
# ---------------------------------------------------------------------------
_SKIP_NAME_SUFFIXES = (".bak", ".tmp", ".backup", ".old", ".orig", ".swp", "~")
_SKIP_NAME_PREFIXES = ("readme", "changelog", "license", "copying", ".#")


def _should_skip_file(name: str) -> bool:
    lo = name.lower()
    if lo.endswith(_SKIP_NAME_SUFFIXES):
        return True
    if lo.startswith(_SKIP_NAME_PREFIXES):
        return True
    return False


# ---------------------------------------------------------------------------
# ScanIndex
# ---------------------------------------------------------------------------

@dataclass
class ScanIndex:
    local_files: dict[str, list[str]]
    local_dbs: dict[str, list[str]]
    remote_files: dict[str, dict[str, list[str]]]
    remote_dbs: dict[str, dict[str, list[str]]]
    scan_errors: list[str] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.scan_errors is None:
            self.scan_errors = []


def _keys_fingerprint(keys: set[str]) -> str:
    return hashlib.sha256("|".join(sorted(keys)).encode()).hexdigest()[:16]


def save_scan_cache(index: ScanIndex, keys: set[str], path: Path) -> None:
    try:
        payload = {
            "timestamp": time.time(),
            "fingerprint": _keys_fingerprint(keys),
            "local_files": index.local_files,
            "local_dbs": index.local_dbs,
            "remote_files": index.remote_files,
            "remote_dbs": index.remote_dbs,
            "scan_errors": index.scan_errors,
        }
        path.write_text(json.dumps(payload, indent=2))
    except OSError:
        pass


def load_scan_cache(keys: set[str], path: Path, max_age_hours: float) -> Optional[ScanIndex]:
    try:
        data = json.loads(path.read_text())
    except Exception:
        return None
    age_h = (time.time() - data.get("timestamp", 0)) / 3600
    if age_h > max_age_hours:
        return None
    if data.get("fingerprint") != _keys_fingerprint(keys):
        return None
    return ScanIndex(
        local_files=data["local_files"],
        local_dbs=data["local_dbs"],
        remote_files=data["remote_files"],
        remote_dbs=data["remote_dbs"],
        scan_errors=data.get("scan_errors", []),
    )


# ---------------------------------------------------------------------------
# Local scanning
# ---------------------------------------------------------------------------

def scan_files_for_keys(keys: set[str], search_dirs: list, search_exts: set, skip_dirs: set, env_path: Optional[Path] = None) -> dict[str, list[str]]:
    active = {k for k in keys if k}
    index: dict[str, list[str]] = {k: [] for k in active}
    seen: dict[str, set[str]] = {k: set() for k in active}
    checked = hits = 0
    frames = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    env_abs = env_path.resolve() if env_path else None
    for base in search_dirs:
        bp = Path(base)
        if not bp.exists():
            continue
        for root, dirnames, filenames in os.walk(bp):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for fn in filenames:
                if _should_skip_file(fn):
                    continue
                if Path(fn).suffix.lower() not in search_exts:
                    continue
                fp = Path(root) / fn
                if env_abs and fp.resolve() == env_abs:
                    continue
                try:
                    if fp.stat().st_size > 2_000_000:
                        continue
                    text = fp.read_text(errors="ignore")
                except (PermissionError, OSError):
                    continue
                checked += 1
                for key in active:
                    if _key_matches(key, text):
                        sp = str(fp)
                        if sp not in seen[key]:
                            seen[key].add(sp)
                            index[key].append(sp)
                            hits += 1
                if checked % 100 == 0:
                    bar_done = min(checked // 200, 20)
                    bar = "█" * bar_done + "░" * (20 - bar_done)
                    print(f"  {next(frames)} [{bar}] {checked:,} files, {hits} hit(s)", end="\r", flush=True)
    print(f"  ✓ Local scan complete — {checked:,} files, {hits} hit(s)        ", flush=True)
    return index


def scan_dbs_for_keys(key_db_refs: dict[str, list]) -> dict[str, list[str]]:
    ref_keys: dict[tuple, list[str]] = {}
    for key, refs in key_db_refs.items():
        for ref in refs:
            ref_keys.setdefault(tuple(_validate_db_ref(*ref)), []).append(key)

    result: dict[str, list[str]] = {k: [] for k in key_db_refs}
    for (db_path, table, col), keys in ref_keys.items():
        dp = Path(db_path)
        if not dp.exists():
            continue
        try:
            con = sqlite3.connect(f"file:{dp}?mode=ro", uri=True)
            try:
                rows = con.execute(f"SELECT {col} FROM {table}").fetchall()
            finally:
                con.close()
        except Exception:
            continue
        for (blob,) in rows:
            if not blob:
                continue
            for key in keys:
                if key and _key_matches(key, blob):
                    hit = f"{db_path}  ({table}.{col})"
                    if hit not in result[key]:
                        result[key].append(hit)
    return result


# ---------------------------------------------------------------------------
# Remote scanning (SSH)
# ---------------------------------------------------------------------------

def _ssh(host: str, user: str, cmd: str, timeout: int = 60, key_path: Optional[Path] = None, stdin_data: Optional[str] = None) -> tuple[int, str, str]:
    ssh_args = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
    ]
    if key_path:
        ssh_args += ["-i", str(key_path)]
    ssh_args += [f"{user}@{host}", cmd]
    result = subprocess.run(ssh_args, capture_output=True, text=True, timeout=timeout,
                            input=stdin_data)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def scan_remote_files_for_keys(host: str, user: str, search_dirs: list, search_exts: set, skip_dirs: set, keys: set[str], key_path: Optional[Path] = None) -> dict[str, list[str]]:
    active = [k for k in keys if k]
    if not active:
        return {}
    # Script reads KEYS from stdin to avoid exposing them in /proc/cmdline
    py = """
import os, sys, pathlib, json, re
data = json.load(sys.stdin)
sys.stdin.close()
EXTS = set(data["exts"])
SKIP = set(data["skip"])
KEYS = data["keys"]
PATS = {k: re.compile(r'(?<![A-Za-z0-9_\\-./])' + re.escape(k) + r'(?![A-Za-z0-9_\\-./])') for k in KEYS}
index = {k: [] for k in KEYS}
seen = {k: set() for k in KEYS}
SKIP_SUFFIXES = (".bak", ".tmp", ".backup", ".old", ".orig", ".swp", "~")
SKIP_PREFIXES = ("readme", "changelog", "license", "copying", ".#")
def _skip_name(n):
    lo = n.lower()
    return lo.endswith(SKIP_SUFFIXES) or lo.startswith(SKIP_PREFIXES)
for base in data["dirs"]:
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for fn in files:
            if _skip_name(fn):
                continue
            if pathlib.Path(fn).suffix.lower() not in EXTS:
                continue
            fp = pathlib.Path(root) / fn
            try:
                if fp.stat().st_size > 2_000_000:
                    continue
                text = fp.read_text(errors='ignore')
            except OSError:
                continue
            for k in KEYS:
                if PATS[k].search(text):
                    s = str(fp)
                    if s not in seen[k]:
                        seen[k].add(s)
                        index[k].append(s)
print(json.dumps(index))
"""
    stdin_data = json.dumps({"keys": active, "exts": list(search_exts), "skip": list(skip_dirs), "dirs": list(search_dirs)})
    rc, out, err = _ssh(host, user, f"python3 -c {__import__('shlex').quote(py)}",
                        timeout=180, key_path=key_path, stdin_data=stdin_data)
    if rc != 0:
        error_msg = err or "ssh error"
        print(f"  WARNING: remote file scan on {host} failed: {error_msg}")
        sentinel: dict[str, list[str]] = {k: [] for k in active}
        sentinel["__scan_error__"] = [f"{host}: {error_msg}"]
        return sentinel
    try:
        return json.loads(out)
    except Exception as exc:
        sentinel = {k: [] for k in active}
        sentinel["__scan_error__"] = [f"{host}: invalid JSON response — {exc}"]
        return sentinel


def scan_remote_dbs_for_keys(host: str, user: str, db_refs: list, keys: set[str], key_path: Optional[Path] = None) -> dict[str, list[str]]:
    active = [k for k in keys if k]
    if not active or not db_refs:
        return {k: [] for k in active}
    # Script reads KEYS and DB_REFS from stdin to avoid exposing them in /proc/cmdline
    py = """
import sqlite3, sys, pathlib, json, re
data = json.load(sys.stdin)
sys.stdin.close()
DB_REFS = data["db_refs"]
KEYS = data["keys"]
PATS = {k: re.compile(r'(?<![A-Za-z0-9_\\-./])' + re.escape(k) + r'(?![A-Za-z0-9_\\-./])') for k in KEYS}
result = {k: [] for k in KEYS}
for db_path, table, col in DB_REFS:
    dp = pathlib.Path(db_path)
    if not dp.exists():
        continue
    try:
        con = sqlite3.connect(f"file:{dp}?mode=ro", uri=True)
        rows = con.execute(f"SELECT {col} FROM {table}").fetchall()
        con.close()
        for (blob,) in rows:
            if not blob:
                continue
            for k in KEYS:
                if PATS[k].search(blob):
                    hit = f"{db_path}  ({table}.{col})"
                    if hit not in result[k]:
                        result[k].append(hit)
    except Exception:
        pass
print(json.dumps(result))
"""
    stdin_data = json.dumps({"keys": active, "db_refs": [list(r) for r in db_refs]})
    rc, out, err = _ssh(host, user, f"python3 -c {__import__('shlex').quote(py)}",
                        timeout=60, key_path=key_path, stdin_data=stdin_data)
    if rc != 0:
        error_msg = err or "ssh error"
        print(f"  WARNING: remote DB scan on {host} failed: {error_msg}")
        sentinel: dict[str, list[str]] = {k: [] for k in active}
        sentinel["__scan_error__"] = [f"{host}: {error_msg}"]
        return sentinel
    try:
        return json.loads(out)
    except Exception as exc:
        sentinel = {k: [] for k in active}
        sentinel["__scan_error__"] = [f"{host}: invalid JSON response — {exc}"]
        return sentinel


# ---------------------------------------------------------------------------
# Build index
# ---------------------------------------------------------------------------

class _Spinner:
    _FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, label: str):
        self._label = label
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        frames = itertools.cycle(self._FRAMES)
        start = time.time()
        while not self._stop.is_set():
            elapsed = int(time.time() - start)
            print(f"  {next(frames)} {self._label} ({elapsed}s)...", end="\r", flush=True)
            time.sleep(0.12)
        print(" " * 72, end="\r", flush=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()


def build_scan_index(
    services: dict,
    env: dict,
    env_path: Optional[Path] = None,
    skip_remote: bool = False,
    cache_path: Optional[Path] = None,
    cache_max_age: float = 4.0,
    no_cache: bool = False,
    remote_hosts: Optional[list[dict]] = None,
    key_path: Optional[Path] = None,
) -> ScanIndex:
    search_dirs, search_exts, skip_dirs, yaml_hosts, _ = load_rotate_keys_config(Path("rotate_keys.yaml"))
    if remote_hosts is None:
        remote_hosts = yaml_hosts

    old_keys: set[str] = set()
    key_db_refs: dict[str, list] = {}
    for svc in services.values():
        if not svc.env_var:
            continue
        k = env.get(svc.env_var, "")
        if not k:
            continue
        old_keys.add(k)
        if svc.db_refs:
            key_db_refs[k] = svc.db_refs

    if not old_keys:
        return ScanIndex({}, {}, {}, {})

    cp = cache_path or Path(".rotate_keys_cache.json")
    if not no_cache:
        cached = load_scan_cache(old_keys, cp, cache_max_age)
        if cached is not None:
            age_min = int((time.time() - cp.stat().st_mtime) / 60)
            print(f"\n  ✓ Using cached scan results ({age_min}m old). Pass --no-cache to force a fresh scan.\n")
            return cached

    print(f"\n  Scanning for {len(old_keys)} key(s) — runs once, then cached for {cache_max_age:.0f}h.")

    local_files = scan_files_for_keys(old_keys, search_dirs, search_exts, skip_dirs, env_path=env_path)
    local_dbs = scan_dbs_for_keys(key_db_refs) if key_db_refs else {k: [] for k in old_keys}

    remote_files: dict[str, dict[str, list[str]]] = {}
    remote_dbs: dict[str, dict[str, list[str]]] = {}
    scan_errors: list[str] = []
    if not skip_remote:
        for rh in remote_hosts:
            label = rh["label"]
            try:
                with _Spinner(f"Scanning {label} files ({rh['host']})"):
                    rf = scan_remote_files_for_keys(rh["host"], rh["user"], rh["search_dirs"], search_exts, skip_dirs, old_keys, key_path=key_path)
                print(f"  ✓ {label} file scan complete.", flush=True)
                with _Spinner(f"Scanning {label} databases ({rh['host']})"):
                    rd = scan_remote_dbs_for_keys(rh["host"], rh["user"], rh["db_refs"], old_keys, key_path=key_path)
                print(f"  ✓ {label} DB scan complete.", flush=True)
                # Extract and remove error sentinels before storing
                for d, tag in ((rf, "__scan_error__"), (rd, "__scan_error__")):
                    if tag in d:
                        scan_errors.extend(d.pop(tag))
                remote_files[label] = rf
                remote_dbs[label] = rd
            except subprocess.TimeoutExpired:
                msg = f"{label} ({rh['host']}): timed out"
                print(f"  ✗ {msg}")
                scan_errors.append(msg)
                remote_files[label] = {k: [] for k in old_keys}
                remote_dbs[label] = {k: [] for k in old_keys}
    else:
        print("  Skipping remote hosts.")

    index = ScanIndex(local_files, local_dbs, remote_files, remote_dbs, scan_errors=scan_errors)
    save_scan_cache(index, old_keys, cp)
    total = sum(len(v) for v in local_files.values())
    print(f"\n  Index ready — {total} local hit(s). Results cached to {cp}\n")
    return index
