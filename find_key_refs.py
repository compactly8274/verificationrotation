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
import sys
from pathlib import Path

SEARCH_DIRS = [
    "/mnt/user/appdata",
    "/mnt/user/data",
    "/boot/config",
]

SEARCH_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".conf", ".config",
    ".xml", ".ini", ".env", ".toml", ".txt", ".cfg",
}

SKIP_DIRS = {
    "logs", "log", "cache", "Cache", "Backups", "backup",
    "MediaCover", "metadata", ".git",
}


def search(key: str, dirs: list[str]) -> list[tuple[str, int, str]]:
    hits = []
    for base in dirs:
        base_path = Path(base)
        if not base_path.exists():
            continue
        for root, dirnames, filenames in os.walk(base_path):
            # Prune skip dirs in-place so os.walk doesn't descend into them
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                if Path(filename).suffix.lower() not in SEARCH_EXTENSIONS:
                    continue
                filepath = Path(root) / filename
                try:
                    text = filepath.read_text(errors="ignore")
                    if key in text:
                        for lineno, line in enumerate(text.splitlines(), 1):
                            if key in line:
                                hits.append((str(filepath), lineno, line.strip()))
                except (PermissionError, OSError):
                    continue
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description="Find old API key references in config files")
    parser.add_argument("--dirs", nargs="+", default=SEARCH_DIRS,
                        help="Directories to search (default: Unraid appdata paths)")
    parser.add_argument("--key", help="Key value to search for (prompted if omitted)")
    args = parser.parse_args()

    print(f"Searching: {', '.join(args.dirs)}")
    print()

    key = args.key
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

        hits = search(key, args.dirs)

        if not hits:
            print(f"  ✓ No references found — safe to rotate\n")
        else:
            print(f"  Found {len(hits)} reference(s):")
            for filepath, lineno, line in hits:
                # Redact the key in display output so it doesn't linger on screen
                display_line = line.replace(key, "***REDACTED***")
                print(f"    {filepath}:{lineno}")
                print(f"      {display_line}")
            print()

        if args.key:
            break  # single key mode — exit after one search
        key = None


if __name__ == "__main__":
    main()
