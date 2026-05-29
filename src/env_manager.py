""".env file read/write utilities."""

from pathlib import Path


def read_env(path: Path) -> dict[str, str]:
    """Read env vars from a .env file, with os.environ as fallback.

    Values from the file take precedence. Variables present in the
    container environment (e.g. from Docker env_file / environment)
    but absent from the file are included so the app works even when
    the .env file isn't mounted inside the container.
    """
    import os

    # Start with container environment as baseline
    result: dict[str, str] = {k: v for k, v in os.environ.items() if v}

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
                out.append(f'{k}="{v}"')
                written.add(k)
                continue
        out.append(line)
    for k, v in updates.items():
        if k not in written:
            out.append(f'{k}="{v}"')
    path.write_text("\n".join(out) + "\n")
