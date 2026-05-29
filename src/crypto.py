"""Symmetric encryption helpers for storing sensitive values at rest.

The Fernet key is derived from settings.SECRET_KEY so that values stored in
the DB cannot be read without the application's secret key.
"""

import base64
import hashlib

from src.config import settings


def _fernet():
    from cryptography.fernet import Fernet
    raw = hashlib.sha256(settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def encrypt_value(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()


def mask_value(value: str) -> str:
    """Return a masked version safe to show in logs or UI without revealing the secret."""
    if len(value) <= 8:
        return "****"
    return value[:4] + "…" + value[-4:]
