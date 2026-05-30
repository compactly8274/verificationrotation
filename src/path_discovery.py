"""Discover service config file locations by pattern-matching appdata directories.

Walks each directory in search_dirs up to MAX_DEPTH levels, matches directory
names against the patterns defined in app_signatures.APP_SIGNATURES, and
returns the absolute path to the config file when found.
"""

import fnmatch
import os
from pathlib import Path

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
