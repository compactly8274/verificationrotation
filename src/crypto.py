"""Symmetric encryption helpers for storing sensitive values at rest.

The Fernet key is derived from settings.SECRET_KEY via PBKDF2 so that values
stored in the DB cannot be read without the application's secret key.
"""

import base64
import hashlib
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.config import settings

logger = logging.getLogger("verificationrotation")

# Fixed salt so that the same SECRET_KEY always derives the same Fernet key.
# Changing this salt or the KDF parameters will invalidate existing ciphertexts.
_KDF_SALT = b"verificationrotation-v2"
_KDF_ITERATIONS = 480_000


def _fernet():
    from cryptography.fernet import Fernet
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=_KDF_ITERATIONS,
    )
    raw = kdf.derive(settings.secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(raw))


def _fernet_legacy():
    """Legacy derivation used for data encrypted before the PBKDF2 upgrade."""
    from cryptography.fernet import Fernet
    raw = hashlib.sha256(settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def encrypt_value(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except Exception:
        # Fallback for data encrypted with the legacy SHA-256 derivation.
        return _fernet_legacy().decrypt(ciphertext.encode()).decode()


def mask_value(value: str) -> str:
    """Return a masked version safe to show in logs or UI without revealing the secret."""
    if len(value) <= 8:
        return "****"
    return value[:4] + "…" + value[-4:]
