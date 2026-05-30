"""Discover service config file locations by pattern-matching appdata directories.

Walks each directory in search_dirs one level deep, matches directory names
against the patterns defined in app_signatures.APP_SIGNATURES, and returns
the absolute path to the config file when found.
"""

import fnmatch
from pathlib import Path

from src.app_signatures import APP_SIGNATURES


def detect_service_paths(search_dirs: list[str]) -> dict[str, str]:
    """Return {service_id: absolute_config_path} for every detected service."""
    found: dict[str, str] = {}

    for base in search_dirs:
        base_path = Path(base)
        if not base_path.is_dir():
            continue
        try:
            entries = sorted(base_path.iterdir())
        except PermissionError:
            continue

        for entry in entries:
            if not entry.is_dir():
                continue
            dirname = entry.name.lower()

            for sid, sig in APP_SIGNATURES.items():
                if sid in found:
                    continue
                for pattern in sig["dir_patterns"]:
                    if fnmatch.fnmatch(dirname, pattern.lower()):
                        # Try all candidate config file paths in order
                        candidates = sig.get("config_file_candidates") or [sig.get("config_file", "")]
                        for candidate in candidates:
                            if not candidate:
                                continue
                            config_path = entry / candidate
                            if config_path.exists():
                                found[sid] = str(config_path)
                                break
                        break  # stop trying patterns for this service once dir matched

    return found
