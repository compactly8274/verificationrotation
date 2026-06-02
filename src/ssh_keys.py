"""SSH key pair generation and storage."""

import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger("verificationrotation")

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


def test_ssh_connection(key_name: str, user: str, host: str) -> tuple[bool, str]:
    """Test SSH connectivity using the named key. Returns (success, message)."""
    key_path = get_ssh_key(key_name)
    if not key_path:
        return False, "SSH key file not found — re-generate the key"
    known_hosts = str(settings.data_dir / "known_hosts")
    try:
        result = subprocess.run(
            [
                "ssh", "-i", str(key_path),
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"UserKnownHostsFile={known_hosts}",
                f"{user}@{host}",
                "echo verificationrotation-ok",
            ],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and "verificationrotation-ok" in result.stdout:
            return True, "Connection successful"
        msg = result.stderr.strip() or f"SSH exited with code {result.returncode}"
        return False, msg
    except subprocess.TimeoutExpired:
        return False, "Connection timed out (10 s)"
    except Exception as exc:
        logger.exception("SSH connection test failed for %s@%s", user, host)
        return False, str(exc)


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
