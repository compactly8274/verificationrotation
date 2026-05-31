""".env file read/write utilities."""

import os
import tempfile
from pathlib import Path

# Env var names that the application actually uses.  Used to filter the
# os.environ baseline so we don't leak unrelated host variables.
_APP_PREFIXES = (
    "ADMIN_", "RESET_", "SECRET_", "BW_", "SCAN_", "CACHE_",
    "AUTO_", "WEBHOOK_", "DOCKER_", "HEALTH_", "DISCOVERY_",
    "COOKIE_", "ENV_", "DATA_", "DESCRIPTIONS_",
)


def _is_app_var(name: str) -> bool:
    """Return True if *name* looks like a variable our app cares about."""
    if name.startswith(_APP_PREFIXES):
        return True
    # UPPERCASE_WITH_UNDERSCORES pattern used by service env vars
    if name == name.upper() and "_" in name and name[0].isalpha():
        return True
    return False


def _escape_env_value(value: str) -> str:
    """Escape a value for safe double-quoted .env representation.

    Handles backslashes, double-quotes, newlines, and dollar signs
    so that values round-trip correctly through Docker Compose and
    Python dotenv parsers.
    """
    value = value.replace("\\", "\\\\")
    value = value.replace('"', '\\"')
    value = value.replace("\n", "\\n")
    value = value.replace("$", "\\$")
    return value


def _unescape_env_value(value: str) -> str:
    """Reverse _escape_env_value for reading."""
    value = value.replace("\\$", "$")
    value = value.replace("\\n", "\n")
    value = value.replace('\\"', '"')
    value = value.replace("\\\\", "\\")
    return value


def read_env(path: Path) -> dict[str, str]:
    """Read env vars from a .env file, with os.environ as fallback.

    Values from the file take precedence. Variables present in the
    container environment (e.g. from Docker env_file / environment)
    but absent from the file are included so the app works even when
    the .env file isn't mounted inside the container.

    Only variables that look like application config (UPPER_SNAKE_CASE
    or known prefixes) are pulled from os.environ, to avoid leaking
    unrelated host environment into the app.
    """
    # Start with container environment as baseline (filtered)
    result: dict[str, str] = {k: v for k, v in os.environ.items() if v and _is_app_var(k)}

    # Override with file values (file is the source of truth for current key values)
    if path.exists():
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
            if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                v = v[1:-1]
                if v and v[0] == '"':
                    v = _unescape_env_value(v)
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
                v = updates[k]
                out.append(f'{k}="{_escape_env_value(v)}"')
                written.add(k)
                continue
        out.append(line)
    for k, v in updates.items():
        if k not in written:
            out.append(f'{k}="{_escape_env_value(v)}"')
    # Atomic write: write to temp file then rename
    dir_path = path.parent
    dir_path.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), suffix=".env.tmp")
    try:
        with os.fdopen(tmp_fd, "w") as f:
            f.write("\n".join(out) + "\n")
        os.replace(tmp_path, str(path))
    except BaseException:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
