"""Symmetric encryption helpers for storing sensitive values at rest.

The Fernet key is derived from settings.SECRET_KEY via PBKDF2 so that values
stored in the DB cannot be read without the application's secret key.
"""

import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.config import settings

logger = logging.getLogger("verificationrotation")

# Default salt for backward compatibility. If KDF_SALT env var is set, it
# overrides this, allowing per-deployment salt uniqueness. A warning is logged
# at startup if the default salt is used.
_DEFAULT_KDF_SALT = b"verificationrotation-v2"
_KDF_ITERATIONS = 480_000


def _get_kdf_salt() -> bytes:
    """Return the KDF salt, preferring the KDF_SALT env var if set."""
    env_salt = os.environ.get("KDF_SALT", "").strip()
    if env_salt:
        return env_salt.encode("utf-8")
    logger.warning(
        "KDF_SALT not set — using default salt. For better security, set a unique "
        "KDF_SALT environment variable. Data encrypted with the default salt is "
        "vulnerable if the SECRET_KEY is compromised."
    )
    return _DEFAULT_KDF_SALT


def _fernet():
    salt = _get_kdf_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    raw = kdf.derive(settings.secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(raw))


def _fernet_legacy():
    """Legacy derivation used for data encrypted before the PBKDF2 upgrade."""
    raw = hashlib.sha256(settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def encrypt_value(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        pass
    # Fallback for data encrypted with the legacy SHA-256 derivation.
    logger.warning("Using legacy key derivation for decryption — consider re-encrypting")
    try:
        return _fernet_legacy().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        raise ValueError("Decryption failed — the SECRET_KEY or KDF_SALT may have changed")


def is_current_derivation(ciphertext: str) -> bool:
    """Return True if `ciphertext` decrypts with the CURRENT key derivation.

    False means either: (a) the ciphertext is on the LEGACY derivation, or
    (b) the ciphertext is corrupt / encrypted with a different key. The
    caller can use this to decide whether to re-encrypt a row.
    """
    try:
        _fernet().decrypt(ciphertext.encode())
        return True
    except Exception:
        return False


def mask_value(value: str) -> str:
    """Return a masked version safe to show in logs or UI without revealing the secret."""
    if len(value) <= 8:
        return "****"
    return value[:4] + "…" + value[-4:]
