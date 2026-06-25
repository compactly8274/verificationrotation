"""Shared scanning helpers — single source of truth for boundary regex and
filename skip logic used by both the legacy module (rotate_keys.py) and the
newer src/ package. Consolidating these prevents drift, which previously caused
stale boundary regexes to silently miss keys adjacent to '=', ':', '+', etc.
"""

import re
from typing import Pattern


# Boundary-safe regex: a key match must not be glued onto an identifier
# character OR a common config-delimiter char (+, :, =, ?, &, %, @).
# This is the single source of truth — all scanner scripts (local + remote +
# CLI + web) import this. Updating it once propagates everywhere.
BOUNDARY_PATTERN: str = r'(?<![A-Za-z0-9_\-./+:=?&%@]){}(?![A-Za-z0-9_\-./+:=?&%@])'

# Inside f-string -> ssh "python3 -c <script>" -> literal regex string,
# the backslashes are doubled so they survive the python -c round-trip.
# (Embedded scripts use this variant.)
BOUNDARY_PATTERN_ESCAPED: str = r'(?<![A-Za-z0-9_\\-./+:=?&%@]){}(?![A-Za-z0-9_\\-./+:=?&%@])'


def key_pattern(key: str) -> Pattern:
    """Compile a boundary-safe regex for a single key."""
    return re.compile(BOUNDARY_PATTERN.format(re.escape(key)))


def key_matches(key: str, text: str) -> bool:
    return bool(key_pattern(key).search(text))


def key_replace(old: str, new: str, text: str) -> str:
    return key_pattern(old).sub(lambda _: new, text)


# ---------------------------------------------------------------------------
# File skip logic
# ---------------------------------------------------------------------------

# Files ending in any of these suffixes are skipped (backups, temp files).
SKIP_NAME_SUFFIXES: tuple = (".bak", ".tmp", ".backup", ".old", ".orig", ".swp", "~")

# Files starting with any of these prefixes are skipped. Note the trailing
# dot — without it, files like `license_key.pem` would be incorrectly skipped
# (they start with "license"). Only whole-doc filenames like `readme.md`,
# `changelog.txt`, or emacs lock files `.#foo` are excluded.
SKIP_NAME_PREFIXES: tuple = ("readme.", "changelog.", ".#")


def should_skip_file(name: str) -> bool:
    lo = name.lower()
    if lo.endswith(SKIP_NAME_SUFFIXES):
        return True
    if lo.startswith(SKIP_NAME_PREFIXES):
        return True
    return False