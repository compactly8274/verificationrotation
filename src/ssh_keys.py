"""SSH key pair generation and storage."""

import os
import subprocess
from pathlib import Path
from typing import Optional

from src.config import settings


def ensure_keys_dir() -> Path:
    keys_dir = settings.data_dir / "ssh_keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    # Restrict permissions
    os.chmod(keys_dir, 0o700)
    return keys_dir


def generate_ssh_key(name: str) -> tuple[str, str]:
    """Generate a new ed25519 key pair. Returns (public_key, private_key_path)."""
    keys_dir = ensure_keys_dir()
    private_path = keys_dir / f"{name}"
    public_path = keys_dir / f"{name}.pub"

    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-C", f"verificationrotation-{name}", "-f", str(private_path), "-N", ""],
        capture_output=True, check=True,
    )
    os.chmod(private_path, 0o600)
    public_key = public_path.read_text().strip()
    return public_key, str(private_path)


def get_ssh_key(name: str) -> Optional[Path]:
    """Return the private key path if it exists."""
    keys_dir = ensure_keys_dir()
    private_path = keys_dir / name
    if private_path.exists():
        return private_path
    return None


def delete_ssh_key(name: str) -> bool:
    keys_dir = ensure_keys_dir()
    private_path = keys_dir / name
    public_path = keys_dir / f"{name}.pub"
    deleted = False
    if private_path.exists():
        private_path.unlink()
        deleted = True
    if public_path.exists():
        public_path.unlink()
    return deleted
