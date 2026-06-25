#!/usr/bin/env python3
"""find_key_refs.py — Search appdata directories for old API key values.

Run this BEFORE rotating each key so you know exactly what needs updating.

Usage:
    python3 find_key_refs.py [--dirs DIR [DIR ...]] [--key VALUE]

Examples:
    # Interactive mode — paste key values one at a time
    python3 find_key_refs.py

    # Search for a specific key across all appdata
    python3 find_key_refs.py --key 9d62cac4b3d54fa596e082c5772d98cb

    # Search a specific directory
    python3 find_key_refs.py --dirs /mnt/user/appdata/sonarr
"""

import argparse
import os
import re
import sys
from pathlib import Path

# Import the boundary regex from the single source of truth so this standalone
# tool stays in sync with the main crawler. Falls back to a hardcoded copy if
# the src package is unavailable (e.g. running from a stripped install).
try:
    from src.scan_helpers import BOUNDARY_PATTERN as _BOUNDARY
except ImportError:
    _BOUNDARY = r'(?<![A-Za-z0-9_\-./+:=?&%@]){}(?![A-Za-z0-9_\-./+:=?&%@])'

# Default search dirs / extensions / skip dirs when rotate_keys.yaml is not available.
SEARCH_DIRS = [
    "/mnt/user/appdata",
    "/mnt/user/data",
    "/mnt/Data",
    "/mnt/tank",
    "/mnt/Dozer",
    "/boot/config",
]

SEARCH_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".conf", ".config",
    ".xml", ".ini", ".env", ".toml", ".txt", ".cfg",
}

SKIP_DIRS = {
    "logs", "log", "cache", "Cache", "Backups", "backup",
    "MediaCover", "metadata", ".git",
    ".trash", ".Recycle.Bin", "lost+found", "System Volume Information",
}

def _try_load_yaml_config() -> tuple[list[str], set[str], set[str]] | None:
    """If a rotate_keys.yaml exists next to this script, load search/dir config from it."""
    yaml_path = Path(__file__).resolve().parent / "rotate_keys.yaml"
    if not yaml_path.exists():
        return None
    try:
        from src.services_registry import load_rotate_keys_config
    except Exception:
        return None
    try:
        search_dirs, search_exts, skip_dirs, _remote_hosts, _services = load_rotate_keys_config(yaml_path)
        return list(search_dirs), set(search_exts), set(skip_dirs)
    except Exception:
        return None


def _key_pattern(key: str) -> re.Pattern:
    return re.compile(_BOUNDARY.format(re.escape(key)))


def search(key: str, dirs: list[str], exts: set[str], skip: set[str]) -> list[tuple[str, int, str]]:
    hits = []
    for base in dirs:
        base_path = Path(base)
        if not base_path.exists():
            continue
        for root, dirnames, filenames in os.walk(base_path):
            # Prune skip dirs in-place so os.walk doesn't descend into them
            dirnames[:] = [d for d in dirnames if d not in skip]
            for filename in filenames:
                if Path(filename).suffix.lower() not in exts:
                    continue
                filepath = Path(root) / filename
                try:
                    text = filepath.read_text(errors="ignore")
                except (PermissionError, OSError):
                    continue
                pat = _key_pattern(key)
                for lineno, line in enumerate(text.splitlines(), 1):
                    if pat.search(line):
                        hits.append((str(filepath), lineno, line.strip()))
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description="Find old API key references in config files")
    parser.add_argument("--dirs", nargs="+", default=None,
                        help="Directories to search (default: rotate_keys.yaml search_dirs, "
                             "or fallback Unraid appdata paths)")
    parser.add_argument("--key", help="Key value to search for (prompted if omitted)")
    parser.add_argument("--key-file", type=Path, help="File containing the key value to search for")
    parser.add_argument("--no-yaml", action="store_true",
                        help="Ignore rotate_keys.yaml and use built-in defaults")
    args = parser.parse_args()

    if args.key:
        print(
            "WARNING: --key exposes the secret in process listings and shell history. "
            "Consider using --key-file instead.",
            file=sys.stderr,
        )

    yaml_cfg = None if args.no_yaml else _try_load_yaml_config()
    if yaml_cfg is not None:
        default_dirs, default_exts, default_skip = yaml_cfg
        print("(using rotate_keys.yaml search_dirs / search_exts / skip_dirs)")
    else:
        default_dirs, default_exts, default_skip = SEARCH_DIRS, SEARCH_EXTENSIONS, SKIP_DIRS

    dirs = args.dirs if args.dirs is not None else default_dirs
    print(f"Searching: {', '.join(dirs)}")
    print()

    key = args.key
    if args.key_file:
        try:
            key = args.key_file.read_text().strip()
        except OSError as exc:
            print(f"ERROR: Could not read key file: {exc}", file=sys.stderr)
            sys.exit(1)

    while True:
        if not key:
            try:
                key = input("Paste old key value (Ctrl-C to quit): ").strip()
            except KeyboardInterrupt:
                print()
                break

        if not key:
            key = None
            continue

        hits = search(key, dirs, default_exts, default_skip)

        if not hits:
            print(f"  ✓ No references found — safe to rotate\n")
        else:
            unique_files = {fp for fp, _ln, _line in hits}
            print(f"  Found {len(hits)} reference(s) across {len(unique_files)} unique file(s):")
            seen = set()
            for filepath, lineno, line in hits:
                # Redact the key in display output so it doesn't linger on screen
                display_line = line.replace(key, "***REDACTED***")
                tag = (filepath, lineno)
                if tag in seen:
                    continue
                seen.add(tag)
                print(f"    {filepath}:{lineno}")
                print(f"      {display_line}")
            print()

        if args.key:
            break  # single key mode — exit after one search
        key = None


if __name__ == "__main__":
    main()
