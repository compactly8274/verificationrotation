"""Format-aware config file read/write for INI, JSON, YAML, TOML, and env files.

All writers preserve surrounding content as much as possible — they only
replace the targeted key's value, leaving comments and other settings intact.
"""

import configparser
import json
import re
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _get_nested(obj: Any, path: list) -> Optional[str]:
    for k in path:
        if isinstance(obj, dict):
            obj = obj.get(k)
        elif isinstance(obj, list) and isinstance(k, int):
            obj = obj[k] if k < len(obj) else None
        else:
            return None
        if obj is None:
            return None
    return str(obj) if obj is not None else None


def _set_nested(obj: Any, path: list, value: Any) -> None:
    for k in path[:-1]:
        if isinstance(k, int):
            obj = obj[k]
        else:
            if k not in obj:
                obj[k] = {}
            obj = obj[k]
    obj[path[-1]] = value


# ---------------------------------------------------------------------------
# INI
# ---------------------------------------------------------------------------

def read_ini(path: str, section: str, key: str) -> Optional[str]:
    try:
        cp = configparser.RawConfigParser()
        cp.read(path, encoding="utf-8")
        val = cp.get(section, key, fallback=None)
        return val.strip().strip("\"'") if val else None
    except Exception:
        return None


def _check_symlink(fp: Path) -> bool:
    """Return True if path is a symlink. Prevents writing through symlinks."""
    try:
        if fp.is_symlink():
            return True
    except OSError:
        pass
    return False


def write_ini(path: str, section: str, key: str, value: str) -> bool:
    """Replace key's value within the named INI section, preserving all formatting."""
    try:
        fp = Path(path)
        if _check_symlink(fp):
            return False
        lines = fp.read_text(errors="ignore").splitlines(keepends=True)
        in_target = False
        replaced = False
        out: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                in_target = stripped[1:-1].strip().lower() == section.lower()
            if in_target and not replaced:
                m = re.match(
                    rf"^(\s*{re.escape(key)}\s*=\s*)(.*)$",
                    line.rstrip("\r\n"),
                    re.IGNORECASE,
                )
                if m:
                    eol = "\r\n" if line.endswith("\r\n") else "\n"
                    out.append(m.group(1) + value + eol)
                    replaced = True
                    continue
            out.append(line)
        if replaced:
            fp.write_text("".join(out))
        return replaced
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def read_json(path: str, *key_path: Any) -> Optional[str]:
    try:
        data = json.loads(Path(path).read_text(errors="ignore"))
        return _get_nested(data, list(key_path))
    except Exception:
        return None


def write_json(path: str, value: str, *key_path: Any) -> bool:
    try:
        fp = Path(path)
        if _check_symlink(fp):
            return False
        data = json.loads(fp.read_text(errors="ignore"))
        _set_nested(data, list(key_path), value)
        fp.write_text(json.dumps(data, indent=2) + "\n")
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# YAML
# ---------------------------------------------------------------------------

def read_yaml(path: str, *key_path: Any) -> Optional[str]:
    try:
        import yaml
        data = yaml.safe_load(Path(path).read_text(errors="ignore"))
        return _get_nested(data, list(key_path))
    except Exception:
        return None


def write_yaml(path: str, value: Any, *key_path: Any) -> bool:
    try:
        import yaml
        fp = Path(path)
        if _check_symlink(fp):
            return False
        data = yaml.safe_load(fp.read_text(errors="ignore")) or {}
        _set_nested(data, list(key_path), value)
        fp.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# TOML  (regex write — tomllib stdlib is read-only)
# ---------------------------------------------------------------------------

def read_toml(path: str, key: str) -> Optional[str]:
    try:
        try:
            import tomllib                  # Python 3.11+
        except ImportError:
            import tomli as tomllib         # type: ignore[no-redef]
        data = tomllib.loads(Path(path).read_text(errors="ignore"))
        return str(data[key]) if key in data else None
    except Exception:
        return None


def write_toml(path: str, key: str, value: str) -> bool:
    """Replace a top-level TOML key using regex (preserves comments and formatting)."""
    try:
        fp = Path(path)
        if _check_symlink(fp):
            return False
        text = fp.read_text(errors="ignore")
        esc = re.escape(key)
        pattern = re.compile(rf'(?m)^({esc}\s*=\s*)["\']?[^"\'\n]*["\']?')
        updated, count = pattern.subn(rf'\g<1>"{value}"', text)
        if not count:
            updated = text.rstrip() + f'\n{key} = "{value}"\n'
        fp.write_text(updated)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ENV-style files  (KEY=value, no sections — e.g. Pi-hole setupVars.conf)
# ---------------------------------------------------------------------------

def read_env_file(path: str, key: str) -> Optional[str]:
    try:
        for line in Path(path).read_text(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
        return None
    except Exception:
        return None


def write_env_file(path: str, key: str, value: str) -> bool:
    try:
        fp = Path(path)
        if fp.exists() and _check_symlink(fp):
            return False
        text = fp.read_text(errors="ignore") if fp.exists() else ""
        # Use word boundary to avoid matching partial keys (e.g., "API" matching "API_KEY")
        pattern = re.compile(rf"(?m)^{re.escape(key)}(?!=)=.*$")
        updated, count = pattern.subn(f"{key}={value}", text)
        if not count:
            updated = text.rstrip() + f"\n{key}={value}\n"
        fp.write_text(updated)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# XML  (ElementTree read, regex write to preserve formatting)
# ---------------------------------------------------------------------------

def read_xml(path: str, tag: str) -> Optional[str]:
    """Read a text element from an XML file by tag name."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.parse(path).getroot()
        el = root.find(f".//{tag}")
        if el is not None and el.text:
            return el.text.strip()
        attr = root.get(tag)
        return attr.strip() if attr else None
    except Exception:
        return None


def write_xml(path: str, tag: str, value: str) -> bool:
    """Replace an XML element's text value using regex to preserve formatting."""
    try:
        fp = Path(path)
        if _check_symlink(fp):
            return False
        text = fp.read_text(errors="ignore")
        pat = re.compile(rf'(<{re.escape(tag)}>)[^<]*(</{re.escape(tag)}>)')
        updated, count = pat.subn(rf'\g<1>{value}\g<2>', text)
        if not count:
            return False
        fp.write_text(updated)
        return True
    except Exception:
        return False
