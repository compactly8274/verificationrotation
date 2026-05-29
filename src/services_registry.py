"""Service definitions and YAML config loading."""

import os
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
_DEFAULT_REMOTE_HOSTS = [
    {
        "label": "TrueNAS",
        "host": "192.168.1.122",
        "user": "root",
        "search_dirs": ["/mnt/Data/appdata"],
        "db_refs": [
            ("/mnt/Data/appdata/prowlarr/prowlarr.db", "Applications", "Settings"),
            ("/mnt/Data/appdata/prowlarr/prowlarr.db", "Indexers", "Settings"),
        ],
    },
]
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


def _xml_tag(path: str, tag: str) -> Callable[[], Optional[str]]:
    def _read() -> Optional[str]:
        try:
            root = ET.parse(path).getroot()
            el = root.find(f".//{tag}")
            return el.text.strip() if el is not None and el.text else None
        except Exception:
            return None
    return _read


def _build_auto_fetch(cfg: Optional[dict]) -> Optional[Callable[[], Optional[str]]]:
    if not cfg:
        return None
    t = cfg.get("type")
    path = cfg.get("path", "")
    if t == "arr_xml":
        return _arr_xml(path)
    if t == "xml_tag":
        return _xml_tag(path, cfg.get("tag", "ApiKey"))
    return None


def _resolve_db_refs(raw_refs: list, groups: dict[str, list]) -> list:
    out: list = []
    for ref in raw_refs:
        if isinstance(ref, str):
            out.extend(groups.get(ref, []))
        else:
            out.append(tuple(ref))
    return out


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
        services[sid] = ServiceDef(
            display_name=raw.get("display_name", sid),
            env_var=raw.get("env_var", ""),
            settings_url=raw.get("settings_url", ""),
            auto_fetch=_build_auto_fetch(raw.get("auto_fetch")),
            db_refs=db_refs,
            note=raw.get("note", ""),
            health_url=raw.get("health_url", ""),
            docker_name=raw.get("docker_name", ""),
            bitwarden=raw.get("bitwarden", {}),
        )

    return search_dirs, search_exts, skip_dirs, remote_hosts, services
