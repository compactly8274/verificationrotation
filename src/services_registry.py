"""Service definitions and YAML config loading."""

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


@dataclass
class ServiceDef:
    display_name: str
    env_var: str
    settings_url: str
    auto_fetch: Optional[Callable[[], Optional[str]]] = None
    auto_write: Optional[Callable[[str], bool]] = None  # write a new key into the config file
    db_refs: list = field(default_factory=list)
    note: str = ""
    health_url: str = ""
    docker_name: str = ""
    bitwarden: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Hard-coded defaults (used if YAML is missing)
# ---------------------------------------------------------------------------

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
_DEFAULT_REMOTE_HOSTS: list = []  # define remote hosts in rotate_keys.yaml → remote_hosts section
_DB_REF_GROUPS: dict[str, list] = {
    "arr_indexer": [
        ("/mnt/user/appdata/sonarr/sonarr.db", "Indexers", "Settings"),
        ("/mnt/user/appdata/radarr/radarr.db", "Indexers", "Settings"),
        ("/mnt/user/appdata/lidarr/lidarr.db", "Indexers", "Settings"),
        ("/mnt/user/appdata/readarr/readarr.db", "Indexers", "Settings"),
    ],
    "arr_dlclient": [
        ("/mnt/user/appdata/sonarr/sonarr.db", "DownloadClients", "Settings"),
        ("/mnt/user/appdata/radarr/radarr.db", "DownloadClients", "Settings"),
        ("/mnt/user/appdata/lidarr/lidarr.db", "DownloadClients", "Settings"),
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
    """Replace <ApiKey>…</ApiKey> in-place using regex to preserve original formatting."""
    _pat = re.compile(r'(<ApiKey>)[^<]*(</ApiKey>)')
    def _write(new_key: str) -> bool:
        try:
            fp = Path(path)
            if fp.is_symlink():
                return False
            text = fp.read_text()
            updated = _pat.sub(rf'\g<1>{new_key}\g<2>', text)
            if updated == text:
                return False  # tag not found — nothing to update
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
    """Replace a named XML tag value in-place using regex to preserve original formatting."""
    _pat = re.compile(rf'(<{re.escape(tag)}>)[^<]*(</{re.escape(tag)}>)')
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


def _sqlite_read(path: str, table: str, column: str, where: str = "") -> Callable[[], Optional[str]]:
    def _read() -> Optional[str]:
        import sqlite3 as _sql
        try:
            uri = f"file:{path}?mode=ro"
            con = _sql.connect(uri, uri=True, timeout=5)
            try:
                q = f"SELECT {column} FROM {table} WHERE {where}" if where else f"SELECT {column} FROM {table} LIMIT 1"
                row = con.execute(q).fetchone()
                return str(row[0]) if row and row[0] is not None else None
            finally:
                con.close()
        except Exception:
            return None
    return _read


def _sqlite_write(path: str, table: str, column: str, where: str = "") -> Callable[[str], bool]:
    def _write(new_value: str) -> bool:
        import sqlite3 as _sql
        try:
            con = _sql.connect(path, timeout=10)
            try:
                q = f"UPDATE {table} SET {column}=?" + (f" WHERE {where}" if where else "")
                con.execute(q, (new_value,))
                con.commit()
                return True
            finally:
                con.close()
        except Exception:
            return False
    return _write


def _build_auto_fetch(cfg: Optional[dict]) -> Optional[Callable[[], Optional[str]]]:
    if not cfg:
        return None
    t = cfg.get("type")
    path = cfg.get("path", "")
    if t == "arr_xml":
        return _arr_xml(path)
    if t == "xml_tag":
        return _xml_tag(path, cfg.get("tag", "ApiKey"))
    if t == "sqlite":
        return _sqlite_read(path, cfg.get("table", ""), cfg.get("column", ""), cfg.get("where", ""))
    if t == "env_file":
        from src.config_io import read_env_file
        return lambda: read_env_file(path, cfg.get("env_key", ""))
    return None


def _build_auto_write(cfg: Optional[dict]) -> Optional[Callable[[str], bool]]:
    """Return a writer for the same config source used by auto_fetch."""
    if not cfg:
        return None
    t = cfg.get("type")
    path = cfg.get("path", "")
    if t == "arr_xml":
        return _arr_xml_write(path)
    if t == "xml_tag":
        return _xml_tag_write(path, cfg.get("tag", "ApiKey"))
    if t == "sqlite":
        return _sqlite_write(path, cfg.get("table", ""), cfg.get("column", ""), cfg.get("where", ""))
    if t == "env_file":
        from src.config_io import write_env_file
        env_key = cfg.get("env_key", "")
        return lambda new: write_env_file(path, env_key, new)
    return None


def _resolve_db_refs(raw_refs: list, groups: dict[str, list]) -> list:
    out: list = []
    for ref in raw_refs:
        if isinstance(ref, str):
            out.extend(groups.get(ref, []))
        else:
            out.append(tuple(ref))
    return out


def build_detected_fetcher(sig: dict, config_path: str):
    """Return an auto_fetch callable for a dynamically-detected service config."""
    if sig.get("password_hash"):
        # Hash is irreversible — always return None so auto_write generates a fresh value
        return lambda: None

    fmt = sig.get("format", "")
    from src.config_io import read_env_file, read_ini, read_json, read_toml, read_yaml

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
        return None

    return _fetch


def build_detected_writer(sig: dict, config_path: str):
    """Return an auto_write callable for a dynamically-detected service config."""
    fmt = sig.get("format", "")
    password_hash = sig.get("password_hash")
    from src.config_io import write_env_file, write_ini, write_json, write_toml, write_yaml

    def _hash(value: str) -> str:
        if password_hash == "bcrypt":
            import bcrypt  # type: ignore[import]
            return bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()
        if password_hash == "sha256_double":
            import hashlib
            return hashlib.sha256(
                hashlib.sha256(value.encode()).hexdigest().encode()
            ).hexdigest()
        return value

    def _write(new_value: str) -> bool:
        stored = _hash(new_value)
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
        return False

    return _write


def load_rotate_keys_config(path: Path) -> tuple:
    """Return (SEARCH_DIRS, SEARCH_EXTS, SKIP_DIRS, REMOTE_HOSTS, SERVICES)."""
    if yaml is None or not path.exists():
        if yaml is None:
            print("  WARNING: PyYAML not installed — using hard-coded defaults.")
        return (
            _DEFAULT_SEARCH_DIRS,
            _DEFAULT_SEARCH_EXTS,
            _DEFAULT_SKIP_DIRS,
            _DEFAULT_REMOTE_HOSTS,
            {},
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
    for sid, raw in (data.get("services") or {}).items():
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
            health_url=raw.get("health_url", ""),
            docker_name=raw.get("docker_name", ""),
            bitwarden=raw.get("bitwarden", {}),
        )

    return search_dirs, search_exts, skip_dirs, remote_hosts, services
