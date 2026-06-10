#!/usr/bin/env python3
"""rotate_keys.py — Guided key rotation that finds, replaces, and verifies every reference.

For each service:
  1. Scans text configs AND *arr SQLite databases for the old key
  2. Prints the settings URL so you can rotate it in the web UI
  3. Reads the new key automatically where possible (config.xml for *arr apps)
     or prompts you to paste it
  4. Replaces old → new in every text config file found
  5. Replaces old → new in every SQLite JSON blob found
  6. Updates your .env file

Run directly on Unraid (needs access to /mnt/user/appdata):
    python3 rotate_keys.py
    python3 rotate_keys.py --service prowlarr
    python3 rotate_keys.py --env /path/to/.env
    python3 rotate_keys.py --auto-discover          # auto-detect config paths & keys
    python3 rotate_keys.py --auto-discover --auto-write  # also write keys to config files
"""

import argparse
import hashlib
import itertools
import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

# ---------------------------------------------------------------------------
# Optional auto-discover modules (src/ package)
# ---------------------------------------------------------------------------

try:
    from src.path_discovery import detect_service_paths, scan_remote_service_configs
    from src.key_discovery import discover_keys, discover_remote_keys, DiscoveryResult
    from src.app_signatures import APP_SIGNATURES
    _AUTO_DISCOVER_AVAILABLE = True
except ImportError:
    _AUTO_DISCOVER_AVAILABLE = False

# ---------------------------------------------------------------------------
# Service definition
# ---------------------------------------------------------------------------

@dataclass
class ServiceDef:
    display_name: str
    env_var: str
    settings_url: str
    # Called after user says they've rotated — returns new key or None
    auto_fetch: Optional[Callable[[], Optional[str]]] = None
    # Called to write a new key into the service's config file
    auto_write: Optional[Callable[[str], bool]] = None
    # SQLite (db_path, table, column) tuples that may store this key
    db_refs: list = field(default_factory=list)
    note: str = ""
    # Health-check URL used for pre/post verification (e.g. http://host:port/ping)
    health_url: str = ""
    # Docker container name to restart after key rotation
    docker_name: str = ""


# ---------------------------------------------------------------------------
# Config loading (YAML or hard-coded fallback)
# ---------------------------------------------------------------------------

DEFAULT_ENV = Path(os.environ.get("ENV_FILE", ".env"))

_DEFAULT_SEARCH_DIRS = ["/mnt/user/appdata", "/boot/config"]
_DEFAULT_SEARCH_EXTS = {".yaml", ".yml", ".json", ".conf", ".config", ".xml", ".ini", ".env", ".toml", ".cfg"}
_DEFAULT_SKIP_DIRS = {
    "logs", "log", "cache", "Cache", "Backups", "backup",
    "MediaCover", "metadata", ".git", "Crash Reports",
    "node_modules", "__pycache__", "venv", "site-packages",
    "dist", "build", "media", "transcodes", "thumbnails",
    "previews", "Metadata", "Plug-in Support", "databases",
    "tv", "movies", "music", "photos", "downloads",
}
_DEFAULT_REMOTE_HOSTS = [
    {
        "label": "TrueNAS",
        "host": "192.168.1.122",
        "user": "root",
        "search_dirs": ["/mnt/Data/appdata"],
        "db_refs": [
            ("/mnt/Data/appdata/prowlarr/prowlarr.db", "Applications", "Settings"),
            ("/mnt/Data/appdata/prowlarr/prowlarr.db", "Indexers",     "Settings"),
        ],
    },
]
_DB_REF_GROUPS: dict[str, list] = {
    "arr_indexer": [
        ("/mnt/user/appdata/sonarr/sonarr.db",   "Indexers",        "Settings"),
        ("/mnt/user/appdata/radarr/radarr.db",   "Indexers",        "Settings"),
        ("/mnt/user/appdata/lidarr/lidarr.db",   "Indexers",        "Settings"),
        ("/mnt/user/appdata/readarr/readarr.db", "Indexers",        "Settings"),
    ],
    "arr_dlclient": [
        ("/mnt/user/appdata/sonarr/sonarr.db",   "DownloadClients", "Settings"),
        ("/mnt/user/appdata/radarr/radarr.db",   "DownloadClients", "Settings"),
        ("/mnt/user/appdata/lidarr/lidarr.db",   "DownloadClients", "Settings"),
        ("/mnt/user/appdata/readarr/readarr.db", "DownloadClients", "Settings"),
    ],
    "prowlarr_apps": [
        ("/mnt/user/appdata/prowlarr/prowlarr.db", "Applications", "Settings"),
    ],
    "bazarr": [
        ("/mnt/user/appdata/bazarr/db/bazarr.db", "system", "configured"),
    ],
}


def _arr_xml(path: str) -> Callable[[], Optional[str]]:
    def _read() -> Optional[str]:
        try:
            root = ET.parse(path).getroot()
            el = root.find("ApiKey")
            return el.text.strip() if el is not None and el.text else None
        except Exception:
            return None
    return _read


def _arr_xml_write(path: str) -> Callable[[str], bool]:
    """Replace <ApiKey>…</ApiKey> in-place using regex to preserve formatting."""
    _pat = re.compile(r'(<ApiKey>)[^<]*(</ApiKey>)')
    def _write(new_key: str) -> bool:
        try:
            fp = Path(path)
            if fp.is_symlink():
                return False
            text = fp.read_text()
            updated = _pat.sub(rf'\g<1>{new_key}\g<2>', text)
            if updated == text:
                return False
            fp.write_text(updated)
            return True
        except Exception:
            return False
    return _write


def _xml_tag(path: str, tag: str) -> Callable[[], Optional[str]]:
    def _read() -> Optional[str]:
        try:
            root = ET.parse(path).getroot()
            el = root.find(f".//{tag}")
            return el.text.strip() if el is not None and el.text else None
        except Exception:
            return None
    return _read


def _xml_tag_write(path: str, tag: str) -> Callable[[str], bool]:
    """Replace a named XML tag value in-place using regex to preserve formatting."""
    def _write(new_key: str) -> bool:
        try:
            fp = Path(path)
            if fp.is_symlink():
                return False
            text = fp.read_text()
            pat = re.compile(rf'(<{re.escape(tag)}>)[^<]*(</{re.escape(tag)}>)')
            updated = pat.sub(rf'\g<1>{new_key}\g<2>', text)
            if updated == text:
                return False
            fp.write_text(updated)
            return True
        except Exception:
            return False
    return _write


_DEFAULT_SERVICES: dict[str, ServiceDef] = {
    "sonarr": ServiceDef(
        display_name="Sonarr", env_var="SONARR_API_KEY",
        settings_url="http://192.168.1.104:8989/settings/general",
        auto_fetch=_arr_xml("/mnt/user/appdata/sonarr/config.xml"),
        auto_write=_arr_xml_write("/mnt/user/appdata/sonarr/config.xml"),
        db_refs=_DB_REF_GROUPS["prowlarr_apps"],
    ),
    "radarr": ServiceDef(
        display_name="Radarr", env_var="RADARR_API_KEY",
        settings_url="http://192.168.1.104:7878/settings/general",
        auto_fetch=_arr_xml("/mnt/user/appdata/radarr/config.xml"),
        auto_write=_arr_xml_write("/mnt/user/appdata/radarr/config.xml"),
        db_refs=_DB_REF_GROUPS["prowlarr_apps"],
    ),
    "lidarr": ServiceDef(
        display_name="Lidarr", env_var="LIDARR_API_KEY",
        settings_url="http://192.168.1.104:8686/settings/general",
        auto_fetch=_arr_xml("/mnt/user/appdata/lidarr/config.xml"),
        auto_write=_arr_xml_write("/mnt/user/appdata/lidarr/config.xml"),
        db_refs=_DB_REF_GROUPS["prowlarr_apps"],
    ),
    "readarr": ServiceDef(
        display_name="Readarr", env_var="READARR_API_KEY",
        settings_url="http://192.168.1.104:8787/settings/general",
        auto_fetch=_arr_xml("/mnt/user/appdata/readarr/config.xml"),
        auto_write=_arr_xml_write("/mnt/user/appdata/readarr/config.xml"),
        db_refs=_DB_REF_GROUPS["prowlarr_apps"],
    ),
    "prowlarr": ServiceDef(
        display_name="Prowlarr", env_var="PROWLARR_API_KEY",
        settings_url="http://192.168.1.122:9696/settings/general",
        auto_fetch=_arr_xml("/mnt/user/appdata/prowlarr/config.xml"),
        auto_write=_arr_xml_write("/mnt/user/appdata/prowlarr/config.xml"),
        db_refs=_DB_REF_GROUPS["arr_indexer"],
        note="After rotating, each *arr app needs its Prowlarr indexer updated — this script handles it automatically via the SQLite DB.",
    ),
    "overseerr": ServiceDef(display_name="Overseerr", env_var="OVERSEERR_API_KEY", settings_url="http://192.168.1.104:5055/settings"),
    "bazarr": ServiceDef(display_name="Bazarr", env_var="BAZARR_API_KEY", settings_url="http://192.168.1.104:6767/settings/general"),
    "jackett": ServiceDef(display_name="Jackett", env_var="JACKETT_API_KEY", settings_url="http://192.168.1.122:9117/UI/Dashboard", db_refs=_DB_REF_GROUPS["arr_indexer"]),
    "autobrr": ServiceDef(display_name="Autobrr", env_var="AUTOBRR_API_KEY", settings_url="http://192.168.1.104:7474/settings/api"),
    "slskd": ServiceDef(display_name="Slskd", env_var="SLSKD_API_KEY", settings_url="http://192.168.1.104:5035/settings"),
    "plex": ServiceDef(display_name="Plex", env_var="PLEX_TOKEN", settings_url="https://app.plex.tv/desktop/#!/settings/account",
                        note="Plex tokens are personal account tokens. Low priority — skip unless you believe it was actually used maliciously."),
    "tautulli": ServiceDef(display_name="Tautulli", env_var="TAUTULLI_API_KEY", settings_url="http://192.168.1.104:8189/settings"),
    "sabnzbd": ServiceDef(display_name="SABnzbd", env_var="SABNZBD_API_KEY", settings_url="http://192.168.1.122:10097/sabnzbd/config/general/", db_refs=_DB_REF_GROUPS["arr_dlclient"]),
    "qbittorrent": ServiceDef(display_name="qBittorrent password", env_var="QBITTORRENT_PASSWORD", settings_url="http://192.168.1.122:10095/",
                               db_refs=_DB_REF_GROUPS["arr_dlclient"], note="Change password in qBittorrent WebUI Options > Web UI > Password."),
    "npm": ServiceDef(display_name="Nginx Proxy Manager  ← DO THIS FIRST (public VPS)", env_var="NPM_PASSWORD", settings_url="http://172.245.73.170:81",
                      note="This is internet-facing. Highest priority."),
    "pangolin": ServiceDef(display_name="Pangolin", env_var="PANGOLIN_API_KEY", settings_url="https://pancakefarts.site/admin/api-keys"),
    "miniflux": ServiceDef(display_name="Miniflux", env_var="MINIFLUX_API_KEY", settings_url="https://mini.pancakefarts.xyz/keys"),
    "traefik": ServiceDef(display_name="Traefik", env_var="", settings_url="https://traefik.pancakefarts.site", note="No secret key to rotate."),
    "gluetun_unraid": ServiceDef(display_name="Gluetun (Unraid)", env_var="GLUETUN_UNRAID_API_KEY", settings_url="",
                                  note="Edit HTTP_CONTROL_SERVER_API_KEY in the Gluetun container's env vars, then restart."),
    "gluetun_truenas": ServiceDef(display_name="Gluetun (TrueNAS)", env_var="GLUETUN_TRUENAS_API_KEY", settings_url="",
                                   note="Edit HTTP_CONTROL_SERVER_API_KEY in the Gluetun container's env vars, then restart."),
    "homebridge": ServiceDef(display_name="Homebridge password", env_var="HOMEBRIDGE_PASSWORD", settings_url="http://192.168.1.104:8581",
                             note="Change under User Accounts in Homebridge settings."),
    "immich": ServiceDef(display_name="Immich", env_var="IMMICH_API_KEY", settings_url="http://192.168.1.104:2283/user-settings?isOpen=api-keys"),
    "truenas": ServiceDef(display_name="TrueNAS", env_var="TRUENAS_API_KEY", settings_url="http://192.168.1.122/ui/apikeys",
                            note="Delete the old key and create a new one."),
    "unifi_os": ServiceDef(display_name="UniFi OS", env_var="UNIFI_OS_API_KEY", settings_url="https://192.168.1.89:11443/proxy/network/integrations"),
    "unifi_ucg": ServiceDef(display_name="UniFi UCG", env_var="UNIFI_UCG_API_KEY", settings_url="https://192.168.1.1/proxy/network/integrations"),
    "qnap": ServiceDef(display_name="QNAP password", env_var="QNAP_PASSWORD", settings_url="https://192.168.1.168"),
    "nut": ServiceDef(display_name="NUT/Peanut password", env_var="NUT_PASSWORD", settings_url="",
                       note="Update in the NUT server config and in all services that reference it."),
}


def _resolve_db_refs(raw_refs: list, groups: dict[str, list]) -> list:
    """Expand named db_ref groups (strings) into raw tuples."""
    out: list = []
    for ref in raw_refs:
        if isinstance(ref, str):
            out.extend(groups.get(ref, []))
        else:
            out.append(tuple(ref))
    return out


def _build_auto_fetch(cfg: Optional[dict]) -> Optional[Callable[[], Optional[str]]]:
    if not cfg:
        return None
    t = cfg.get("type")
    path = cfg.get("path", "")
    if t == "arr_xml":
        return _arr_xml(path)
    if t == "xml_tag":
        return _xml_tag(path, cfg.get("tag", "ApiKey"))
    if t == "ini":
        section, key = cfg.get("section", ""), cfg.get("key", "")
        try:
            from src.config_io import read_ini
            return lambda: read_ini(path, section, key)
        except ImportError:
            return None
    if t == "json":
        key_path = cfg.get("keys", [])
        try:
            from src.config_io import read_json
            return lambda: read_json(path, *key_path)
        except ImportError:
            return None
    if t == "yaml":
        key_path = cfg.get("keys", [])
        try:
            from src.config_io import read_yaml
            return lambda: read_yaml(path, *key_path)
        except ImportError:
            return None
    if t == "toml":
        key = cfg.get("key", "")
        try:
            from src.config_io import read_toml
            return lambda: read_toml(path, key)
        except ImportError:
            return None
    if t == "env":
        key = cfg.get("key", "")
        try:
            from src.config_io import read_env_file
            return lambda: read_env_file(path, key)
        except ImportError:
            return None
    return None


def _build_auto_write(cfg: Optional[dict]) -> Optional[Callable[[str], bool]]:
    """Build an auto_write callable from a YAML auto_fetch config block."""
    if not cfg:
        return None
    t = cfg.get("type")
    path = cfg.get("path", "")
    if t == "arr_xml":
        return _arr_xml_write(path)
    if t == "xml_tag":
        return _xml_tag_write(path, cfg.get("tag", "ApiKey"))
    if t == "ini":
        section, key = cfg.get("section", ""), cfg.get("key", "")
        try:
            from src.config_io import write_ini
            return lambda v: write_ini(path, section, key, v)
        except ImportError:
            return None
    if t == "json":
        key_path = cfg.get("keys", [])
        try:
            from src.config_io import write_json
            return lambda v: write_json(path, v, *key_path)
        except ImportError:
            return None
    if t == "yaml":
        key_path = cfg.get("keys", [])
        try:
            from src.config_io import write_yaml
            return lambda v: write_yaml(path, v, *key_path)
        except ImportError:
            return None
    if t == "toml":
        key = cfg.get("key", "")
        try:
            from src.config_io import write_toml
            return lambda v: write_toml(path, key, v)
        except ImportError:
            return None
    if t == "env":
        key = cfg.get("key", "")
        try:
            from src.config_io import write_env_file
            return lambda v: write_env_file(path, key, v)
        except ImportError:
            return None
    return None


def build_detected_fetcher(sig: dict, config_path: str) -> Optional[Callable[[], Optional[str]]]:
    """Return auto_fetch callable for a dynamically-detected service config."""
    if sig.get("password_hash"):
        return lambda: None

    fmt = sig.get("format", "")
    try:
        from src.config_io import read_env_file, read_ini, read_json, read_toml, read_xml, read_yaml
    except ImportError:
        return None

    def _fetch() -> Optional[str]:
        if fmt == "ini":
            return read_ini(config_path, sig["ini_section"], sig["ini_key"])
        if fmt == "json":
            return read_json(config_path, *sig["json_path"])
        if fmt == "yaml":
            return read_yaml(config_path, *sig["yaml_path"])
        if fmt == "toml":
            return read_toml(config_path, sig["toml_key"])
        if fmt == "env":
            return read_env_file(config_path, sig["env_key"])
        if fmt == "arr_xml":
            return read_xml(config_path, "ApiKey")
        if fmt == "xml_tag":
            return read_xml(config_path, sig.get("xml_tag", "ApiKey"))
        return None

    return _fetch


def build_detected_writer(sig: dict, config_path: str) -> Optional[Callable[[str], bool]]:
    """Return auto_write callable for a dynamically-detected service config."""
    fmt = sig.get("format", "")
    password_hash = sig.get("password_hash")
    try:
        from src.config_io import write_env_file, write_ini, write_json, write_toml, write_xml, write_yaml
    except ImportError:
        return None

    def _hash_val(value: str) -> str:
        if password_hash == "bcrypt":
            try:
                import bcrypt
                return bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()
            except ImportError:
                return value
        if password_hash == "sha256_double":
            return hashlib.sha256(
                hashlib.sha256(value.encode()).hexdigest().encode()
            ).hexdigest()
        return value

    def _write(new_value: str) -> bool:
        stored = _hash_val(new_value)
        if fmt == "ini":
            return write_ini(config_path, sig["ini_section"], sig["ini_key"], stored)
        if fmt == "json":
            return write_json(config_path, stored, *sig["json_path"])
        if fmt == "yaml":
            return write_yaml(config_path, stored, *sig["yaml_path"])
        if fmt == "toml":
            return write_toml(config_path, sig["toml_key"], stored)
        if fmt == "env":
            return write_env_file(config_path, sig["env_key"], stored)
        if fmt == "arr_xml":
            return write_xml(config_path, "ApiKey", stored)
        if fmt == "xml_tag":
            return write_xml(config_path, sig.get("xml_tag", "ApiKey"), stored)
        return False

    return _write


def load_rotate_keys_config(path: Path) -> tuple:
    """Return (SEARCH_DIRS, SEARCH_EXTS, SKIP_DIRS, REMOTE_HOSTS, SERVICES, ENV_MIRRORS).
    Falls back to hard-coded defaults if YAML is unavailable or file missing."""
    if yaml is None or not path.exists():
        if yaml is None:
            print("  WARNING: PyYAML not installed — using hard-coded defaults.")
        return (
            _DEFAULT_SEARCH_DIRS,
            _DEFAULT_SEARCH_EXTS,
            _DEFAULT_SKIP_DIRS,
            _DEFAULT_REMOTE_HOSTS,
            _DEFAULT_SERVICES,
            [],
        )

    data = yaml.safe_load(path.read_text()) or {}

    search_dirs = data.get("search_dirs", _DEFAULT_SEARCH_DIRS)
    search_exts = set(data.get("search_exts", _DEFAULT_SEARCH_EXTS))
    skip_dirs = set(data.get("skip_dirs", _DEFAULT_SKIP_DIRS))
    remote_hosts = []
    for rh in data.get("remote_hosts", _DEFAULT_REMOTE_HOSTS):
        remote_hosts.append({
            "label": rh["label"],
            "host": rh["host"],
            "user": rh["user"],
            "search_dirs": rh.get("search_dirs", []),
            "db_refs": [tuple(r) for r in rh.get("db_refs", [])],
        })

    db_groups = {**_DB_REF_GROUPS}
    for name, refs in (data.get("db_ref_groups") or {}).items():
        db_groups[name] = [tuple(r) for r in refs]

    services: dict[str, ServiceDef] = {}
    for sid, raw in (data.get("services") or _DEFAULT_SERVICES).items():
        if isinstance(raw, ServiceDef):
            services[sid] = raw
            continue
        db_refs_raw = raw.get("db_refs", [])
        db_refs = _resolve_db_refs(db_refs_raw, db_groups)
        af_cfg = raw.get("auto_fetch")
        services[sid] = ServiceDef(
            display_name=raw.get("display_name", sid),
            env_var=raw.get("env_var", ""),
            settings_url=raw.get("settings_url", ""),
            auto_fetch=_build_auto_fetch(af_cfg),
            auto_write=_build_auto_write(af_cfg),
            db_refs=db_refs,
            note=raw.get("note", ""),
        )

    env_mirrors = [str(p) for p in data.get("env_mirrors", [])]
    return search_dirs, search_exts, skip_dirs, remote_hosts, services, env_mirrors


_CONFIG_PATH = Path(__file__).with_suffix(".yaml")
SEARCH_DIRS, SEARCH_EXTS, SKIP_DIRS, REMOTE_HOSTS, SERVICES, ENV_MIRRORS = load_rotate_keys_config(_CONFIG_PATH)


# ---------------------------------------------------------------------------
# Auto-discover
# ---------------------------------------------------------------------------

def apply_auto_discover(services: dict, env: dict, search_dirs: list, skip_dirs: set, remote_hosts: Optional[list] = None) -> None:
    """Scan filesystem for known service config paths and augment services in-place.

    Sets auto_fetch and auto_write on services that don't have them yet, then
    reports current key values found in config files that differ from .env.
    If remote_hosts is provided, also scans remote hosts via SSH.
    """
    if not _AUTO_DISCOVER_AVAILABLE:
        print("  WARNING: Auto-discover modules not found (src/ package missing).")
        print("  Run from the repository root directory.")
        return

    print("\n  ─── Auto-Discover: Service Config Paths ──────────────────────")
    detected = detect_service_paths(search_dirs)

    augmented: list[str] = []
    for sid, config_path in detected.items():
        if sid not in services:
            continue
        svc = services[sid]
        sig = APP_SIGNATURES.get(sid)
        if not sig:
            continue
        changed = False
        if svc.auto_fetch is None:
            fetcher = build_detected_fetcher(sig, config_path)
            if fetcher is not None:
                svc.auto_fetch = fetcher
                changed = True
        if svc.auto_write is None:
            writer = build_detected_writer(sig, config_path)
            if writer is not None:
                svc.auto_write = writer
        if changed:
            print(f"    ✓ {svc.display_name}: {config_path}")
            augmented.append(sid)

    if augmented:
        print(f"  Augmented {len(augmented)} service(s) with auto-fetch: {', '.join(augmented)}")
    else:
        print("  No new service configs discovered (all already configured, or no matches)")

    # Key discovery: find current values that differ from .env
    print("\n  ─── Auto-Discover: Current Key Values ────────────────────────")
    results = discover_keys(services, env, search_dirs, skip_dirs)
    if results:
        print(f"  Found {len(results)} key value(s) that differ from .env:")
        for r in results:
            masked = r.value[:4] + "…" + r.value[-4:] if len(r.value) > 8 else "***"
            print(f"    {r.display_name:<22} [{masked}]  via {r.strategy} ({r.confidence})  ← {r.source_file}")
        print()
        print("  These service configs hold values not yet in your .env.")
        print("  Run the rotation menu to sync them.")
    else:
        print("  All discovered service keys match .env (or no differences found)")
    print()

    # Remote host discovery
    if not remote_hosts:
        return

    print("  ─── Auto-Discover: Remote Host Config Paths ──────────────────")
    for rh in remote_hosts:
        label = rh.get("label", rh.get("host", "remote"))
        host = rh.get("host", "")
        user = rh.get("user", "root")
        rh_dirs = rh.get("search_dirs", search_dirs)
        key_path = rh.get("key_path")

        if not host:
            continue

        print(f"\n  Scanning {label} ({host})...")
        try:
            remote_results = discover_remote_keys(
                host=host,
                user=user,
                services=services,
                env=env,
                search_dirs=rh_dirs,
                key_path=key_path,
            )
        except Exception as exc:
            print(f"  WARNING: Remote scan of {label} failed: {exc}")
            continue

        if remote_results:
            print(f"  Found {len(remote_results)} key value(s) on {label} that differ from .env:")
            for r in remote_results:
                masked = r.value[:4] + "…" + r.value[-4:] if len(r.value) > 8 else "***"
                print(f"    {r.display_name:<22} [{masked}]  <- {r.source_file}")
        else:
            print(f"  All discovered keys on {label} match .env (or no differences found)")
    print()


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def _ssh(host: str, user: str, cmd: str, timeout: int = 60) -> tuple[int, str, str]:
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
         "-o", "StrictHostKeyChecking=accept-new",
         f"{user}@{host}", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def scan_remote_files_for_keys(host: str, user: str, search_dirs: list, keys: set[str]) -> dict[str, list[str]]:
    """Single SSH call — scan remote files for all keys at once."""
    active = [k for k in keys if k]
    if not active:
        return {}
    py = f"""
import os, pathlib, json, re
EXTS = {set(SEARCH_EXTS)!r}
SKIP = {SKIP_DIRS!r}
KEYS = {active!r}
PATS = {{k: re.compile(r'(?<![A-Za-z0-9_\\-./])' + re.escape(k) + r'(?![A-Za-z0-9_\\-./])') for k in KEYS}}
index = {{k: [] for k in KEYS}}
seen = {{k: set() for k in KEYS}}
SKIP_SUFFIXES = (".bak", ".tmp", ".backup", ".old", ".orig", ".swp", "~")
SKIP_PREFIXES = ("readme", "changelog", "license", "copying", ".#")
def _skip_name(n):
    lo = n.lower()
    return lo.endswith(SKIP_SUFFIXES) or lo.startswith(SKIP_PREFIXES)
for base in {search_dirs!r}:
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
    rc, out, err = _ssh(host, user, f"python3 -c {shlex.quote(py)}", timeout=180)
    if rc != 0:
        print(f"  WARNING: remote file scan on {host} failed: {err or 'ssh error'}")
        return {k: [] for k in active}
    try:
        return json.loads(out)
    except Exception:
        return {k: [] for k in active}


def replace_in_remote_files(host: str, user: str, old: str, new: str, filepaths: list) -> list[str]:
    if not filepaths:
        return []
    py = f"""
import shutil, pathlib, re
OLD = {old!r}
NEW = {new!r}
PAT = re.compile(r'(?<![A-Za-z0-9_\\-./])' + re.escape(OLD) + r'(?![A-Za-z0-9_\\-./])')
for fp_str in {filepaths!r}:
    fp = pathlib.Path(fp_str)
    try:
        text = fp.read_text(errors='ignore')
        if PAT.search(text):
            tmp = fp.with_suffix(fp.suffix + '.tmp')
            tmp.write_text(PAT.sub(lambda _: NEW, text))
            shutil.move(str(tmp), str(fp))
            print(fp)
    except OSError as e:
        print(f'WARNING: {{e}}')
"""
    rc, out, err = _ssh(host, user, f"python3 -c {shlex.quote(py)}")
    if rc != 0:
        print(f"  WARNING: remote file replace on {host} failed: {err or 'ssh error'}")
        return []
    return [l for l in out.splitlines() if l and not l.startswith("WARNING")]


def scan_remote_dbs_for_keys(host: str, user: str, db_refs: list, keys: set[str]) -> dict[str, list[str]]:
    """Single SSH call — scan remote DBs for all keys at once."""
    active = [k for k in keys if k]
    if not active or not db_refs:
        return {k: [] for k in active}
    py = f"""
import sqlite3, pathlib, json, re
DB_REFS = {db_refs!r}
KEYS = {active!r}
PATS = {{k: re.compile(r'(?<![A-Za-z0-9_\\-./])' + re.escape(k) + r'(?![A-Za-z0-9_\\-./])') for k in KEYS}}
result = {{k: [] for k in KEYS}}
for db_path, table, col in DB_REFS:
    dp = pathlib.Path(db_path)
    if not dp.exists():
        continue
    try:
        con = sqlite3.connect(f"file:{{dp}}?mode=ro", uri=True)
        rows = con.execute(f"SELECT {{col}} FROM {{table}}").fetchall()
        con.close()
        for (blob,) in rows:
            if not blob:
                continue
            for k in KEYS:
                if PATS[k].search(blob):
                    hit = f"{{db_path}}  ({{table}}.{{col}})"
                    if hit not in result[k]:
                        result[k].append(hit)
    except Exception:
        pass
print(json.dumps(result))
"""
    rc, out, err = _ssh(host, user, f"python3 -c {shlex.quote(py)}", timeout=60)
    if rc != 0:
        print(f"  WARNING: remote DB scan on {host} failed: {err or 'ssh error'}")
        return {k: [] for k in active}
    try:
        return json.loads(out)
    except Exception:
        return {k: [] for k in active}


def replace_in_remote_dbs(host: str, user: str, old: str, new: str, db_refs: list) -> list[str]:
    if not db_refs:
        return []
    py = f"""
import sqlite3, shutil, pathlib, re
OLD = {old!r}
NEW = {new!r}
PAT = re.compile(r'(?<![A-Za-z0-9_\\-./])' + re.escape(OLD) + r'(?![A-Za-z0-9_\\-./])')
seen = set()
for db_path, table, col in {db_refs!r}:
    key = (db_path, table, col)
    if key in seen: continue
    seen.add(key)
    dp = pathlib.Path(db_path)
    if not dp.exists(): continue
    try:
        backup = dp.with_suffix('.db.bak')
        shutil.copy2(dp, backup)
        con = sqlite3.connect(dp)
        rows = con.execute(f"SELECT rowid, {{col}} FROM {{table}}").fetchall()
        updated = 0
        for rowid, blob in rows:
            if blob and PAT.search(blob):
                con.execute(f"UPDATE {{table}} SET {{col}}=? WHERE rowid=?", (PAT.sub(lambda _: NEW, blob), rowid))
                updated += 1
        if updated:
            con.commit()
            print(f"{{db_path}}  ({{table}}.{{col}}, {{updated}} row(s))")
        else:
            backup.unlink(missing_ok=True)
        con.close()
    except Exception as e:
        print(f'WARNING: {{e}}')
"""
    rc, out, err = _ssh(host, user, f"python3 -c {shlex.quote(py)}")
    if rc != 0:
        print(f"  WARNING: remote DB replace on {host} failed: {err or 'ssh error'}")
        return []
    return [l for l in out.splitlines() if l and not l.startswith("WARNING")]


# ---------------------------------------------------------------------------
# .env helpers
# ---------------------------------------------------------------------------

def read_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.exists():
        return result
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        # strip surrounding quotes: KEY="value" or KEY='value'
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
            v = v[1:-1]
        result[k] = v
    return result


def write_env(path: Path, updates: dict[str, str]) -> None:
    lines = path.read_text().splitlines() if path.exists() else []
    written = set()
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k in updates:
                out.append(f"{k}={updates[k]}")
                written.add(k)
                continue
        out.append(line)
    for k, v in updates.items():
        if k not in written:
            out.append(f"{k}={v}")
    path.write_text("\n".join(out) + "\n")


# ---------------------------------------------------------------------------
# Rotation state (resume support)
# ---------------------------------------------------------------------------

STATE_FILE_NAME = ".rotate_keys_state.json"


def _state_path(env_path: Path) -> Path:
    return env_path.parent / STATE_FILE_NAME


def load_state(env_path: Path) -> dict:
    sp = _state_path(env_path)
    try:
        return json.loads(sp.read_text())
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}


def save_state(env_path: Path, state: dict) -> None:
    sp = _state_path(env_path)
    sp.write_text(json.dumps(state, indent=2))


def clear_state(env_path: Path) -> None:
    sp = _state_path(env_path)
    if sp.exists():
        sp.unlink()
        print(f"  Cleared state file: {sp}")


def _key_hash(key: str) -> str:
    """One-way hash for storing in state without exposing the actual key."""
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Exact-match helpers
# ---------------------------------------------------------------------------
_BOUNDARY = r'(?<![A-Za-z0-9_\-./]){}(?![A-Za-z0-9_\-./])'


def _key_pattern(key: str) -> re.Pattern:
    return re.compile(_BOUNDARY.format(re.escape(key)))


def _key_matches(key: str, text: str) -> bool:
    return bool(_key_pattern(key).search(text))


def _key_replace(old: str, new: str, text: str) -> str:
    return _key_pattern(old).sub(lambda _: new, text)


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
# Health checks
# ---------------------------------------------------------------------------

def _health_check(url: str, expected_key: Optional[str] = None, timeout: int = 10) -> tuple[bool, str]:
    """Return (ok, message). If expected_key is given, verify it in response."""
    if not url:
        return True, "No health URL configured"
    try:
        import urllib.request
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if expected_key and expected_key in body:
                return False, "Response still contains old key"
            return True, f"HTTP {resp.status}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------

def _backup_dir(env_path: Path) -> Path:
    ts = time.strftime("%Y%m%d_%H%M%S")
    bp = env_path.parent / ".rotate_keys_backups" / ts
    bp.mkdir(parents=True, exist_ok=True)
    return bp


def _backup_file(src: Path, backup_dir: Path) -> Path:
    dest = backup_dir / src.name
    shutil.copy2(src, dest)
    return dest


def _restore_from_backup(backup_dir: Path, targets: list[Path]) -> None:
    for target in targets:
        src = backup_dir / target.name
        if src.exists():
            shutil.copy2(src, target)
            print(f"  Restored {target} from backup")


# ---------------------------------------------------------------------------
# Docker restart
# ---------------------------------------------------------------------------

def restart_docker_container(name: str) -> None:
    if not name:
        return
    try:
        import docker
        client = docker.from_env()
        container = client.containers.get(name)
        container.restart()
        print(f"  ✓ Restarted Docker container '{name}'")
    except docker.errors.NotFound:
        print(f"  WARNING: Docker container '{name}' not found")
    except Exception as exc:
        print(f"  WARNING: Could not restart Docker container '{name}': {exc}")


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

AUDIT_FILE_NAME = ".rotate_keys_audit.jsonl"


def _audit_path(env_path: Path) -> Path:
    return env_path.parent / AUDIT_FILE_NAME


def log_audit(
    env_path: Path,
    service_id: str,
    old_key_hash: str,
    new_key_hash: str,
    files_changed: int,
    dbs_changed: int,
    success: bool,
    message: str = "",
) -> None:
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "service": service_id,
        "old_key_hash": old_key_hash,
        "new_key_hash": new_key_hash,
        "files_changed": files_changed,
        "dbs_changed": dbs_changed,
        "success": success,
        "message": message,
    }
    ap = _audit_path(env_path)
    with ap.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Search helpers
# ---------------------------------------------------------------------------

def scan_files_for_keys(keys: set[str], env_path: Optional[Path] = None) -> dict[str, list[str]]:
    """Walk filesystem ONCE, return {key: [files]} for all keys simultaneously."""
    active = {k for k in keys if k}
    index: dict[str, list[str]] = {k: [] for k in active}
    seen: dict[str, set[str]] = {k: set() for k in active}
    checked = hits = 0
    frames = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    env_abs = env_path.resolve() if env_path else None
    for base in SEARCH_DIRS:
        bp = Path(base)
        if not bp.exists():
            continue
        for root, dirnames, filenames in os.walk(bp):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if _should_skip_file(fn):
                    continue
                if Path(fn).suffix.lower() not in SEARCH_EXTS:
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
                    print(f"  {next(frames)} [{bar}] {checked:,} files, {hits} hit(s)",
                          end="\r", flush=True)
    print(f"  ✓ Local scan complete — {checked:,} files, {hits} hit(s)        ", flush=True)
    return index


def replace_in_files(old: str, new: str, filepaths: list[str]) -> list[str]:
    """Replace old→new (boundary-matched) in the given file list."""
    changed = []
    for fp_str in filepaths:
        fp = Path(fp_str)
        try:
            text = fp.read_text(errors="ignore")
            if not _key_matches(old, text):
                continue
            updated = _key_replace(old, new, text)
            tmp = fp.with_suffix(fp.suffix + ".tmp")
            tmp.write_text(updated)
            shutil.move(str(tmp), str(fp))
            changed.append(fp_str)
        except (PermissionError, OSError) as e:
            print(f"  WARNING: Could not update {fp}: {e}")
    return changed


def scan_dbs_for_keys(key_db_refs: dict[str, list]) -> dict[str, list[str]]:
    """Scan local SQLite DBs for multiple keys in a single pass per DB."""
    ref_keys: dict[tuple, list[str]] = {}
    for key, refs in key_db_refs.items():
        for ref in refs:
            ref_keys.setdefault(tuple(ref), []).append(key)

    result: dict[str, list[str]] = {k: [] for k in key_db_refs}
    for (db_path, table, col), keys in ref_keys.items():
        dp = Path(db_path)
        if not dp.exists():
            continue
        try:
            con = sqlite3.connect(f"file:{dp}?mode=ro", uri=True)
            rows = con.execute(f"SELECT {col} FROM {table}").fetchall()
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


class _Spinner:
    """Print an animated spinner + elapsed time while a blocking call runs in the main thread."""

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

    def __enter__(self) -> "_Spinner":
        self._thread.start()
        return self

    def __exit__(self, *_) -> None:
        self._stop.set()
        self._thread.join()


def _keys_fingerprint(keys: set[str]) -> str:
    return hashlib.sha256("|".join(sorted(keys)).encode()).hexdigest()[:16]


def save_scan_cache(index: "ScanIndex", keys: set[str], path: Path) -> None:
    try:
        payload = {
            "timestamp": time.time(),
            "fingerprint": _keys_fingerprint(keys),
            "local_files": index.local_files,
            "local_dbs": index.local_dbs,
            "remote_files": index.remote_files,
            "remote_dbs": index.remote_dbs,
        }
        path.write_text(json.dumps(payload, indent=2))
    except OSError:
        pass


def load_scan_cache(keys: set[str], path: Path, max_age_hours: float) -> "Optional[ScanIndex]":
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
    )


# ---------------------------------------------------------------------------
# Rotation log  (tracks when each service key was last rotated)
# ---------------------------------------------------------------------------

_ROTATION_LOG_PATH = Path(".rotate_keys_log.json")


def load_rotation_log(path: Path = _ROTATION_LOG_PATH) -> dict[str, float]:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def save_rotation_log(log: dict[str, float], path: Path = _ROTATION_LOG_PATH) -> None:
    try:
        path.write_text(json.dumps(log, indent=2))
    except OSError:
        pass


def days_since_rotated(service_id: str, log: dict[str, float]) -> Optional[float]:
    ts = log.get(service_id)
    if ts is None:
        return None
    return (time.time() - ts) / 86400


@dataclass
class ScanIndex:
    """Pre-built search results for all active old keys — built once, used many times."""
    local_files:  dict[str, list[str]]                    # key → [local file paths]
    local_dbs:    dict[str, list[str]]                    # key → [db hit strings]
    remote_files: dict[str, dict[str, list[str]]]         # label → key → [remote paths]
    remote_dbs:   dict[str, dict[str, list[str]]]         # label → key → [db hit strings]


def build_scan_index(
    services: dict,
    env: dict,
    env_path: Optional[Path] = None,
    skip_remote: bool = False,
    cache_path: Optional[Path] = None,
    cache_max_age: float = 4.0,
    no_cache: bool = False,
) -> ScanIndex:
    """Walk the filesystem and all DBs ONCE for every active old key."""
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
            print(f"\n  ✓ Using cached scan results ({age_min}m old). "
                  f"Pass --no-cache to force a fresh scan.\n")
            return cached

    print(f"\n  Scanning for {len(old_keys)} key(s) — runs once, then cached for "
          f"{cache_max_age:.0f}h.")

    local_files = scan_files_for_keys(old_keys, env_path=env_path)
    local_dbs   = scan_dbs_for_keys(key_db_refs) if key_db_refs else {k: [] for k in old_keys}

    remote_files: dict[str, dict[str, list[str]]] = {}
    remote_dbs:   dict[str, dict[str, list[str]]] = {}
    if not skip_remote:
        for rh in REMOTE_HOSTS:
            label = rh["label"]
            try:
                with _Spinner(f"Scanning {label} files ({rh['host']})"):
                    rf = scan_remote_files_for_keys(
                        rh["host"], rh["user"], rh["search_dirs"], old_keys
                    )
                print(f"  ✓ {label} file scan complete.", flush=True)
                with _Spinner(f"Scanning {label} databases ({rh['host']})"):
                    rd = scan_remote_dbs_for_keys(
                        rh["host"], rh["user"], rh["db_refs"], old_keys
                    )
                print(f"  ✓ {label} DB scan complete.", flush=True)
                remote_files[label] = rf
                remote_dbs[label]   = rd
            except subprocess.TimeoutExpired:
                print(f"  ✗ {label} timed out — skipping. Use --skip-remote to avoid this.")
                remote_files[label] = {k: [] for k in old_keys}
                remote_dbs[label]   = {k: [] for k in old_keys}
    else:
        print("  Skipping remote hosts (--skip-remote).")

    index = ScanIndex(local_files, local_dbs, remote_files, remote_dbs)
    save_scan_cache(index, old_keys, cp)
    total = sum(len(v) for v in local_files.values())
    print(f"\n  Index ready — {total} local hit(s). Results cached to {cp}\n")
    return index


def replace_in_dbs(old: str, new: str, db_refs: list) -> list[str]:
    changed = []
    seen: set[tuple] = set()
    for db_path_str, table, col in db_refs:
        key = (db_path_str, table, col)
        if key in seen:
            continue
        seen.add(key)
        dp = Path(db_path_str)
        if not dp.exists():
            continue
        try:
            backup = dp.with_suffix(".db.bak")
            shutil.copy2(dp, backup)
            con = sqlite3.connect(dp)
            cur = con.execute(f"SELECT rowid, {col} FROM {table}")
            rows = cur.fetchall()
            updated = 0
            for rowid, blob in rows:
                if blob and _key_matches(old, blob):
                    con.execute(
                        f"UPDATE {table} SET {col}=? WHERE rowid=?",
                        (_key_replace(old, new, blob), rowid),
                    )
                    updated += 1
            if updated:
                con.commit()
                changed.append(f"{db_path_str}  ({table}.{col}, {updated} row(s))")
            else:
                backup.unlink(missing_ok=True)
            con.close()
        except Exception as e:
            print(f"  WARNING: SQLite update failed for {db_path_str}: {e}")
    return changed


# ---------------------------------------------------------------------------
# Core rotation logic
# ---------------------------------------------------------------------------

def rotate(
    service_id: str,
    svc: ServiceDef,
    env: dict[str, str],
    env_path: Path,
    index: ScanIndex,
    state: Optional[dict] = None,
    rotation_log: Optional[dict] = None,
    dry_run: bool = False,
    non_interactive: bool = False,
    backup_dir: Optional[Path] = None,
    auto_write_enabled: bool = False,
) -> bool:
    """Rotate a single service. Returns True on success."""
    print(f"\n{'─'*60}")
    print(f"  {svc.display_name}")
    print(f"{'─'*60}")

    if not svc.env_var:
        print(f"  {svc.note}")
        return True

    old_key = env.get(svc.env_var, "")
    if not old_key:
        print(f"  ${svc.env_var} not set in {env_path.resolve()} — skipping")
        print(f"  (run with --env /correct/path/.env if your .env is elsewhere)")
        input("  [Press Enter to continue] ")
        return True

    if svc.note:
        print(f"  Note: {svc.note}")

    # Pre-flight health check
    if svc.health_url:
        ok, msg = _health_check(svc.health_url)
        if not ok:
            print(f"  ✗ Pre-flight health check failed: {msg}")
            log_audit(env_path, service_id, _key_hash(old_key), "", 0, 0, False, f"Pre-flight failed: {msg}")
            return False
        print(f"  ✓ Pre-flight health check passed ({msg})")

    # Look up pre-built index — instant, no filesystem walk
    file_hits = index.local_files.get(old_key, [])
    db_hits   = index.local_dbs.get(old_key, [])
    remote_file_hits = {label: d.get(old_key, []) for label, d in index.remote_files.items() if d.get(old_key)}
    remote_db_hits   = {label: d.get(old_key, []) for label, d in index.remote_dbs.items()   if d.get(old_key)}

    if file_hits:
        print(f"  Local text files ({len(file_hits)}):")
        for f in file_hits:
            print(f"    {f}")
    if db_hits:
        print(f"  Local SQLite databases ({len(db_hits)}):")
        for d in db_hits:
            print(f"    {d}")
    for label, hits in remote_file_hits.items():
        print(f"  {label} text files ({len(hits)}):")
        for f in hits:
            print(f"    {f}")
    for label, hits in remote_db_hits.items():
        print(f"  {label} SQLite databases ({len(hits)}):")
        for d in hits:
            print(f"    {d}")
    if not file_hits and not db_hits and not remote_file_hits and not remote_db_hits:
        print("  No references found outside of .env")

    has_hits = any([file_hits, db_hits, remote_file_hits, remote_db_hits])

    # Non-interactive mode: skip services that need manual UI unless auto_fetch works
    if non_interactive:
        if not svc.auto_fetch and (svc.settings_url or has_hits):
            print(f"  [non-interactive] Skipping — requires manual UI interaction")
            log_audit(env_path, service_id, _key_hash(old_key), "", 0, 0, False, "Skipped in non-interactive mode")
            return False

    if not has_hits and not svc.settings_url and not svc.auto_fetch:
        print("  No references found and no settings URL — updating .env only.")
        if dry_run:
            print(f"  [dry-run] Would update ${svc.env_var} in {env_path}")
            return True
        new_key = input("  Paste new key/password (or blank to skip): ").strip()
        if not new_key or new_key == old_key:
            print("  No change — skipping")
            return True
        env[svc.env_var] = new_key
        write_env(env_path, {svc.env_var: new_key})
        print(f"  ✓ Updated {env_path}  (${svc.env_var})")
        return True

    if not non_interactive:
        if svc.settings_url:
            print(f"\n  → Open: {svc.settings_url}")
        auto_hint = " (will be read automatically)" if svc.auto_fetch else ""
        print(f"  → Rotate / regenerate the key there{auto_hint}, then press Enter.")
        input("  [Press Enter when done] ")

    # Try auto-read
    new_key: Optional[str] = None
    if svc.auto_fetch:
        new_key = svc.auto_fetch()
        if new_key and new_key != old_key:
            masked = new_key[:6] + "..." + new_key[-4:]
            print(f"  ✓ Auto-read new key from config file: {masked}")
        else:
            new_key = None
            print("  Could not auto-read (key unchanged or file missing)")

    if not non_interactive and not new_key:
        new_key = input("  Paste new key/password: ").strip()

    if not new_key or new_key == old_key:
        print("  No change — skipping")
        return True

    # Dry-run: show what would change without writing
    if dry_run:
        print("\n  [dry-run] Would replace in:")
        for f in file_hits:
            print(f"    {f}")
        for d in db_hits:
            print(f"    {d}")
        for label, hits in remote_file_hits.items():
            for f in hits:
                print(f"    [{label}] {f}")
        for label, hits in remote_db_hits.items():
            for d in hits:
                print(f"    [{label}] {d}")
        if svc.auto_write and auto_write_enabled:
            print(f"  [dry-run] Would auto-write new key to service config file")
        print(f"  [dry-run] Would update {env_path}  (${svc.env_var})")
        return True

    # Take backups before mutation
    if backup_dir:
        for f in file_hits:
            _backup_file(Path(f), backup_dir)
        for db_path_str, _, _ in (svc.db_refs or []):
            dp = Path(db_path_str)
            if dp.exists():
                _backup_file(dp, backup_dir)

    # Write new key back to service config file if --auto-write was requested
    if svc.auto_write and auto_write_enabled:
        if svc.auto_write(new_key):
            print(f"  ✓ Auto-wrote new key to service config file")
        else:
            print(f"  WARNING: Could not auto-write to service config file (manual update may be needed)")

    # Apply replacements — local
    print(f"\n  Replacing in files...")
    changed_files = replace_in_files(old_key, new_key, file_hits)
    changed_dbs   = replace_in_dbs(old_key, new_key, svc.db_refs) if svc.db_refs else []

    # Apply replacements — remote
    remote_changed_files: dict[str, list[str]] = {}
    remote_changed_dbs:   dict[str, list[str]] = {}
    for rh in REMOTE_HOSTS:
        label = rh["label"]
        hits = remote_file_hits.get(label, [])
        rcf = replace_in_remote_files(rh["host"], rh["user"], old_key, new_key, hits)
        rcd = replace_in_remote_dbs(rh["host"], rh["user"], old_key, new_key, rh["db_refs"])
        if rcf:
            remote_changed_files[label] = rcf
        if rcd:
            remote_changed_dbs[label] = rcd

    # Update .env
    env[svc.env_var] = new_key
    write_env(env_path, {svc.env_var: new_key})
    for _mirror in ENV_MIRRORS:
        _mp = Path(_mirror)
        if _mp.parent.exists():
            write_env(_mp, {svc.env_var: new_key})
            print(f"  ✓ Mirrored → {_mp}")

    total = (len(changed_files) + len(changed_dbs)
             + sum(len(v) for v in remote_changed_files.values())
             + sum(len(v) for v in remote_changed_dbs.values()))
    if changed_files:
        print(f"  ✓ Updated {len(changed_files)} local text file(s)")
        for f in changed_files:
            print(f"    {f}")
    if changed_dbs:
        print(f"  ✓ Updated {len(changed_dbs)} local database(s)")
        for d in changed_dbs:
            print(f"    {d}")
    for label, hits in remote_changed_files.items():
        print(f"  ✓ Updated {len(hits)} {label} text file(s)")
        for f in hits:
            print(f"    {f}")
    for label, hits in remote_changed_dbs.items():
        print(f"  ✓ Updated {len(hits)} {label} database(s)")
        for d in hits:
            print(f"    {d}")
    print(f"  ✓ Updated {env_path}  (${svc.env_var})")
    print(f"  ✓ Done — {total} location(s) updated")
    if rotation_log is not None:
        rotation_log[service_id] = time.time()
        save_rotation_log(rotation_log)

    # Post-flight health check
    if svc.health_url:
        ok, msg = _health_check(svc.health_url, expected_key=old_key)
        if not ok:
            print(f"  ✗ Post-flight health check failed: {msg}")
        else:
            print(f"  ✓ Post-flight health check passed ({msg})")

    # Restart Docker container if configured
    if svc.docker_name:
        restart_docker_container(svc.docker_name)

    # Audit log
    log_audit(env_path, service_id, _key_hash(old_key), _key_hash(new_key),
              len(changed_files), len(changed_dbs), True)

    # Persist rotation state so we can resume if interrupted later.
    if state is not None:
        state.setdefault("completed", [])
        if service_id not in state["completed"]:
            state["completed"].append(service_id)
        state.setdefault("services", {})
        state["services"][service_id] = {
            "status": "completed",
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "old_key_hash": _key_hash(old_key),
            "new_key_hash": _key_hash(new_key),
        }
        save_state(env_path, state)

    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Guided API key rotation")
    parser.add_argument("--env", default=str(DEFAULT_ENV), metavar="PATH",
                        help=f"Path to .env file (default: {DEFAULT_ENV})")
    parser.add_argument("--service", choices=list(SERVICES.keys()), metavar="ID",
                        help="Rotate one service non-interactively")
    parser.add_argument("--list", action="store_true", help="List all service IDs and exit")
    parser.add_argument("--skip-remote", action="store_true",
                        help="Skip SSH scan of remote hosts (TrueNAS etc.)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Ignore cached scan results and rescan from scratch")
    parser.add_argument("--cache-max-age", type=float, default=4.0, metavar="HOURS",
                        help="Max age of cached scan results in hours (default: 4)")
    parser.add_argument("--clear-state", action="store_true",
                        help="Remove any saved rotation state and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would change without writing anything")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Skip services that require manual UI interaction")
    parser.add_argument("--backup", action="store_true",
                        help="Create timestamped backups before mutating files/DBs")
    parser.add_argument("--rollback", metavar="TIMESTAMP",
                        help="Restore from a previous backup (e.g. 20260527_143022)")
    parser.add_argument("--skip-recent", type=float, default=3.0, metavar="DAYS",
                        help="Skip services rotated within this many days in 'rotate all' (default: 3)")
    parser.add_argument("--include-recent", action="store_true",
                        help="Include recently-rotated services in 'rotate all'")
    parser.add_argument("--auto-discover", action="store_true",
                        help="Scan appdata for service config files, set up auto-fetch/write "
                             "for discovered services, and report keys that differ from .env")
    parser.add_argument("--auto-write", action="store_true",
                        help="After rotation, write the new key back to the service config file "
                             "(only takes effect for services with auto-fetch/write support)")
    args = parser.parse_args()

    env_path = Path(args.env)

    if args.clear_state:
        clear_state(env_path)
        return

    if args.list:
        for sid, svc in SERVICES.items():
            af = "✓ auto-fetch" if svc.auto_fetch else ""
            aw = "✓ auto-write" if svc.auto_write else ""
            caps = "  ".join(x for x in [af, aw] if x)
            print(f"{sid:<20} {svc.display_name:<35} {caps}")
        return

    # Rollback mode
    if args.rollback:
        backup_dir = env_path.parent / ".rotate_keys_backups" / args.rollback
        if not backup_dir.exists():
            print(f"Backup not found: {backup_dir}")
            sys.exit(1)
        print(f"Rolling back from {backup_dir}...")
        for f in backup_dir.iterdir():
            target = env_path.parent / f.name
            if target.exists():
                shutil.copy2(f, target)
                print(f"  Restored {target}")
        print("Rollback complete.")
        return

    env = read_env(env_path)
    state = load_state(env_path)
    completed: set[str] = set(state.get("completed", []))
    backup_dir: Optional[Path] = _backup_dir(env_path) if args.backup else None
    rotation_log = load_rotation_log()

    # Startup diagnostic
    services_with_keys = [s for s in SERVICES.values() if s.env_var]
    loaded_count = sum(1 for s in services_with_keys if env.get(s.env_var))
    if not env_path.exists():
        print(f"\n  WARNING: .env not found at {env_path.resolve()}")
        print(f"  Use --env /path/to/.env to specify the correct path.\n")
    else:
        print(f"\n  Loaded {len(env)} variable(s) from {env_path.resolve()}")
        print(f"  Found keys for {loaded_count}/{len(services_with_keys)} known services")
        if loaded_count == 0:
            print(f"  WARNING: No service keys found — check your .env format (KEY=value).\n")

    if ENV_MIRRORS:
        print(f"  env_mirrors: {len(ENV_MIRRORS)} additional .env path(s) updated on rotation")
        for _mp in ENV_MIRRORS:
            print(f"    {_mp}")

    # Auto-discover: scan filesystem for service config paths and current key values
    if args.auto_discover:
        apply_auto_discover(SERVICES, env, SEARCH_DIRS, SKIP_DIRS, remote_hosts=REMOTE_HOSTS)

    # Offer resume if a previous rotation was interrupted
    if completed and not args.service:
        print("\n" + "="*60)
        print("  Previous rotation state found")
        print("="*60)
        print(f"  Completed ({len(completed)}): {', '.join(sorted(completed))}")
        resume = input("  Resume from where you left off? [Y/n]: ").strip().lower()
        if resume and resume not in ("y", "yes"):
            print("  Discarding state — starting fresh.")
            clear_state(env_path)
            completed = set()
            state = {}
        else:
            print("  Resuming...\n")

    # Build the scan index once — all keys, one filesystem walk
    index = build_scan_index(
        SERVICES, env,
        env_path=env_path,
        skip_remote=args.skip_remote,
        no_cache=args.no_cache,
        cache_max_age=args.cache_max_age,
    )

    if args.service:
        rotate(args.service, SERVICES[args.service], env, env_path, index,
               state=state, rotation_log=rotation_log,
               dry_run=args.dry_run, non_interactive=args.non_interactive,
               backup_dir=backup_dir, auto_write_enabled=args.auto_write)
        return

    # Interactive menu — ordered by priority
    priority_order = [
        "npm", "pangolin", "miniflux",          # internet-facing first
        "prowlarr",                              # most downstream deps
        "qbittorrent", "sabnzbd",               # download clients (referenced in all *arrs)
        "sonarr", "radarr", "lidarr", "readarr", "overseerr", "bazarr",
        "jackett", "autobrr", "slskd",
        "tautulli", "truenas", "immich",
        "gluetun_unraid", "gluetun_truenas",
        "homebridge", "unifi_os", "unifi_ucg", "qnap", "nut",
        "plex",                                  # lowest priority
    ]

    service_list = [(sid, SERVICES[sid]) for sid in priority_order if sid in SERVICES]

    while True:
        print("\n" + "="*60)
        print("  Key Rotation Menu  (ordered by priority)")
        print("="*60)
        for i, (sid, svc) in enumerate(service_list, 1):
            current = env.get(svc.env_var, "") if svc.env_var else ""
            age = days_since_rotated(sid, rotation_log)
            age_str = f"  ← rotated {age:.0f}d ago" if age is not None else ""
            if sid in completed:
                status = "✓ done"
            elif current:
                status = "✓"
            else:
                status = "–"
            auto_cap = " [A]" if (svc.auto_fetch or svc.auto_write) else ""
            print(f"  {i:2}. [{status}] {svc.display_name}{auto_cap}{age_str}")
        skip_days = args.skip_recent if not args.include_recent else 0
        print(f"\n   a. Rotate ALL remaining (skips services rotated within {skip_days:.0f}d)")
        print("   q. Quit")
        if any(svc.auto_fetch or svc.auto_write for _, svc in service_list):
            print("   [A] = auto-fetch/write capable")

        choice = input("\nEnter number, 'a', or 'q': ").strip().lower()

        if choice == "q":
            break
        elif choice == "a":
            rotated_count = skipped_count = no_key_count = 0
            for sid, svc in service_list:
                if sid in completed:
                    continue
                if not svc.env_var or not env.get(svc.env_var):
                    no_key_count += 1
                    continue
                age = days_since_rotated(sid, rotation_log)
                if not args.include_recent and age is not None and age < skip_days:
                    print(f"  Skipping {svc.display_name} (rotated {age:.0f}d ago)")
                    skipped_count += 1
                    continue
                rotate(sid, svc, env, env_path, index, state=state,
                       rotation_log=rotation_log,
                       dry_run=args.dry_run, non_interactive=args.non_interactive,
                       backup_dir=backup_dir, auto_write_enabled=args.auto_write)
                env = read_env(env_path)
                rotated_count += 1
            if rotated_count == 0:
                print(f"\n  Nothing rotated — {skipped_count} skipped (recent), "
                      f"{no_key_count} without keys.")
                if skipped_count > 0:
                    print(f"  Use --include-recent to rotate them anyway.")
            remaining = {sid for sid, _ in service_list if sid not in completed}
            if not remaining:
                clear_state(env_path)
                completed = set()
                state = {}
                print("\n  🎉 All services rotated — state cleared. Next run starts fresh.")
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(service_list):
                    sid, svc = service_list[idx]
                    rotate(sid, svc, env, env_path, index, state=state,
                           rotation_log=rotation_log,
                           dry_run=args.dry_run, non_interactive=args.non_interactive,
                           backup_dir=backup_dir, auto_write_enabled=args.auto_write)
                    completed = set(state.get("completed", []))
                    env = read_env(env_path)
                else:
                    print("  Out of range")
            except ValueError:
                print("  Invalid input")


if __name__ == "__main__":
    main()
