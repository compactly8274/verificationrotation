"""Discover current API key/password values from config files on disk.

Discovery is attempted in order of confidence:
  1. auto_fetch   — reads directly from the service's known config file (arr_xml, xml_tag)
  2. env_file     — finds .env / *.env files in search_dirs containing the env var
  3. compose      — finds docker-compose.yml files declaring the env var
  4. structured   — parses JSON / YAML / TOML / INI files for a key matching the env var name
  5. remote_config — SSH scan of a remote host's config files
"""

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.crypto import encrypt_value, mask_value
from src.models import DiscoveredKey

logger = logging.getLogger("verificationrotation")

_ENV_FILENAMES = {
    ".env", "env", ".env.local", ".env.prod", ".env.production", ".env.example",
    ".env.development", ".env.staging", ".env.test", ".env.override",
    "setupvars.conf", "miniflux.env", "paperless.conf", "docker-compose.env",
    "nzbget.conf",
}
_COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
_STRUCTURED_EXTS = {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".xml",
}
_XML_FILENAMES = {"config.xml", "serverconfig.xml"}
_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB
_MAX_DEPTH = 10


@dataclass
class DiscoveryResult:
    service_id: str
    env_var: str
    display_name: str
    value: str          # plaintext — caller is responsible for encrypting before storage
    source_file: str
    confidence: str     # "high" | "medium" | "low"
    strategy: str       # "auto_fetch" | "env_file" | "compose" | "structured" | "remote_config"


# ---------------------------------------------------------------------------
# Text-level extraction helpers
# ---------------------------------------------------------------------------

def _extract_from_text(text: str, env_var: str) -> Optional[str]:
    """Try several regex patterns to pull env_var's value from raw file text."""
    esc = re.escape(env_var)
    patterns = [
        # KEY=value  /  KEY="value"  (shell, .env, inline docker-compose)
        rf'(?m)^[ \t]*{esc}[ \t]*=[ \t]*["\']?([^\s"\'\'#\n][^\s"\'\'#\n]*)',
        # - KEY=value  (docker-compose env list item)
        rf'(?m)^[ \t]*-[ \t]*{esc}=[ \t]*["\']?([^\s"\'\'#\n]+)',
        # KEY: value  (YAML block)
        rf'(?m)^[ \t]*{esc}[ \t]*:[ \t]*["\']?([^\s"\'\'#\n][^\s"\'\'#\n]*)',
        # "KEY": "value"  (JSON / YAML inline)
        rf'["\']?{esc}["\']?\s*:\s*["\']([^"\']+)["\']',
        # <KEY>value</KEY>  (XML element)
        rf'<{esc}>([^<]+)</{esc}>',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            val = m.group(1).strip().strip('"\'')
            if len(val) >= 8:
                return val
    return None


def _search_obj(obj, env_var: str) -> Optional[str]:
    """Recursively search a parsed Python object for a key matching env_var."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k.upper() == env_var.upper():
                if isinstance(v, str) and len(v) >= 8:
                    return v
            if isinstance(v, (dict, list)):
                r = _search_obj(v, env_var)
                if r:
                    return r
    elif isinstance(obj, list):
        for item in obj:
            r = _search_obj(item, env_var)
            if r:
                return r
    return None


def _parse_structured(fp: Path) -> Optional[object]:
    text = fp.read_text(errors="ignore")
    ext = fp.suffix.lower()
    try:
        if ext == ".json":
            return json.loads(text)
        if ext in (".yaml", ".yml"):
            import yaml
            return yaml.safe_load(text)
        if ext == ".toml":
            try:
                import tomllib                  # Python 3.11+
            except ImportError:
                try:
                    import tomli as tomllib     # backport
                except ImportError:
                    return None
            return tomllib.loads(text)
        if ext in (".ini", ".conf", ".cfg"):
            import configparser
            cp = configparser.ConfigParser()
            cp.read_string(text)
            return {s: dict(cp[s]) for s in cp.sections()}
        if ext == ".xml":
            import xml.etree.ElementTree as ET
            root = ET.fromstring(text)
            return {el.tag: el.text for el in root.iter() if el.text and el.text.strip()}
    except Exception as exc:
        logger.debug("Could not parse %s as %s: %s", fp.name, ext or "structured", exc)
    return None


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------

def discover_keys(
    services: dict,
    env: dict[str, str],
    search_dirs: list[str],
    skip_dirs: set[str],
) -> list[DiscoveryResult]:
    """Return discovered key values that differ from what's currently in env.

    Only services with an env_var defined are considered.  A service is removed
    from the remaining set as soon as one result is found for it (highest-
    confidence strategy wins).
    """
    results: list[DiscoveryResult] = []
    found_ids: set[str] = set()

    # ── Strategy 1: auto_fetch ──────────────────────────────────────────────────────────────────────
    for sid, svc in services.items():
        if not svc.env_var or not svc.auto_fetch:
            continue
        try:
            fetched = svc.auto_fetch()
        except Exception:
            fetched = None
        if not fetched or len(fetched) < 8:
            continue
        if fetched == env.get(svc.env_var, ""):
            continue  # already in sync
        # Try to recover the config file path from the closure
        source = "config file"
        try:
            if svc.auto_fetch.__closure__:
                for cell in svc.auto_fetch.__closure__:
                    cv = cell.cell_contents
                    if isinstance(cv, str) and ("/" in cv or "\\" in cv):
                        source = cv
                        break
        except Exception:
            pass
        results.append(DiscoveryResult(
            service_id=sid, env_var=svc.env_var, display_name=svc.display_name,
            value=fetched, source_file=source, confidence="high", strategy="auto_fetch",
        ))
        found_ids.add(sid)

    # Map env_var → (sid, display_name) for services not yet found
    remaining: dict[str, tuple[str, str]] = {
        svc.env_var: (sid, svc.display_name)
        for sid, svc in services.items()
        if svc.env_var and sid not in found_ids
    }
    if not remaining:
        return results

    # ── Strategies 2–4: filesystem scan ────────────────────────────────────────────────────────────────
    for base in search_dirs:
        base_path = Path(base)
        if not base_path.exists():
            continue

        base_depth = len(base_path.parts)
        for root_str, dirs, files in os.walk(base_path, followlinks=False):
            root = Path(root_str)
            depth = len(root.parts) - base_depth
            if depth >= _MAX_DEPTH:
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

            for fname in files:
                if not remaining:
                    return results  # all found

                fp = root / fname
                fname_lower = fname.lower()
                ext = fp.suffix.lower()

                is_env = fname_lower in _ENV_FILENAMES or fname_lower.endswith(".env")
                is_compose = fname_lower in _COMPOSE_NAMES
                is_structured = ext in _STRUCTURED_EXTS

                if not (is_env or is_compose or is_structured):
                    continue
                if ext == ".xml" and fname_lower not in {"config.xml", "serverconfig.xml"}:
                    continue  # only parse XML files we know are small service configs

                try:
                    if fp.stat().st_size > _MAX_FILE_BYTES:
                        continue
                    text = fp.read_text(errors="ignore")
                except OSError:
                    continue

                strategy = "env_file" if is_env else ("compose" if is_compose else "structured")
                confidence = "high" if is_env else "medium"

                to_remove: list[str] = []
                for env_var, (sid, dname) in remaining.items():
                    val = _extract_from_text(text, env_var)
                    if not val and is_structured:
                        parsed = _parse_structured(fp)
                        if parsed:
                            val = _search_obj(parsed, env_var)
                    if val and val != env.get(env_var, ""):
                        results.append(DiscoveryResult(
                            service_id=sid, env_var=env_var, display_name=dname,
                            value=val, source_file=str(fp),
                            confidence=confidence, strategy=strategy,
                        ))
                        found_ids.add(sid)
                        to_remove.append(env_var)

                for k in to_remove:
                    remaining.pop(k, None)

    return results


def discover_remote_keys(
    host: str,
    user: str,
    services: dict,
    env: dict[str, str],
    search_dirs: list[str],
    key_path: Optional[str] = None,
) -> list[DiscoveryResult]:
    """Scan a remote host for service API keys via SSH.

    Returns DiscoveryResult entries for services where the remote config value
    differs from what's currently in env.
    """
    from src.path_discovery import scan_remote_service_configs

    remote_data = scan_remote_service_configs(host, user, search_dirs, key_path)
    results: list[DiscoveryResult] = []

    for sid, data in remote_data.items():
        value = data.get("value")
        if not value or len(value) < 8:
            continue
        svc = services.get(sid)
        if svc is None:
            continue
        if not svc.env_var:
            continue
        if value == env.get(svc.env_var, ""):
            continue
        results.append(DiscoveryResult(
            service_id=sid,
            env_var=svc.env_var,
            display_name=svc.display_name,
            value=value,
            source_file=data.get("path", "remote"),
            confidence="high",
            strategy="remote_config",
        ))

    return results


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def _dedupe_results(results: Sequence[DiscoveryResult]) -> list[DiscoveryResult]:
    """Collapse multiple DiscoveryResults for the same (service_id, env_var).

    Discovery can produce more than one result per pair when a key shows
    up in multiple files (e.g. a compose file and an .env file). We keep
    the LAST occurrence, which is what `discover_keys` would naturally
    surface as the "most recently found" value.
    """
    by_pair: dict[tuple[str, str], DiscoveryResult] = {}
    for r in results:
        by_pair[(r.service_id, r.env_var)] = r
    return list(by_pair.values())


async def upsert_discovered_keys(
    session: AsyncSession,
    results: Sequence[DiscoveryResult],
) -> list[dict]:
    """Insert/update DiscoveredKey rows for each unique (service_id, env_var).

    Behavior:
    - Dedupes `results` by (service_id, env_var); last write wins.
    - For each (service_id, env_var) pair, finds the existing row (if any).
    - If an existing row has `applied_at` set (the user already applied
      that key), the new value is NOT persisted and the existing row is
      left untouched. Otherwise, the existing row is updated in place
      (encrypted value, source_file, confidence, strategy) — preserving
      the primary key and avoiding a delete/insert that would lose any
      audit metadata.
    - Returns a list of dicts mirroring the API response shape, with the
      masked value rather than the plaintext.

    The caller is responsible for committing the session.
    """
    deduped = _dedupe_results(results)
    stored: list[dict] = []

    for r in deduped:
        existing = (await session.execute(
            select(DiscoveredKey).where(
                (DiscoveredKey.service_id == r.service_id)
                & (DiscoveredKey.env_var == r.env_var)
            )
        )).scalar_one_or_none()

        if existing is not None and existing.applied_at is not None:
            # User already applied a discovered key for this pair. Don't
            # clobber the applied row — the new value is just an
            # observation; the user can clear+rediscover if they want a
            # fresh row.
            continue

        encrypted = encrypt_value(r.value)
        if existing is None:
            existing = DiscoveredKey(
                service_id=r.service_id,
                env_var=r.env_var,
                display_name=r.display_name,
                value_encrypted=encrypted,
                source_file=r.source_file,
                confidence=r.confidence,
                strategy=r.strategy,
            )
            session.add(existing)
        else:
            existing.value_encrypted = encrypted
            existing.source_file = r.source_file
            existing.confidence = r.confidence
            existing.strategy = r.strategy

        stored.append({
            "service_id": r.service_id,
            "env_var": r.env_var,
            "display_name": r.display_name,
            "value_masked": mask_value(r.value),
            "source_file": r.source_file,
            "confidence": r.confidence,
            "strategy": r.strategy,
        })

    return stored
