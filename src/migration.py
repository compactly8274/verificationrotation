"""Re-encryption migration for discovered keys at rest.

Background
----------
Discovered key values are stored in the DB as Fernet ciphertexts derived
from SECRET_KEY via a key-derivation function (KDF). When the KDF
parameters (salt, algorithm, iteration count) change, every existing
ciphertext becomes undecryptable under the new derivation — there's no
in-place way to upgrade without first decrypting with the OLD key and
re-encrypting with the NEW key.

This module provides a one-shot migration that:

  1. Reads every row in `discovered_keys`.
  2. Attempts to decrypt using the CURRENT derivation.
  3. If that fails, falls back to the LEGACY SHA-256 derivation.
  4. Re-encrypts the plaintext with the CURRENT derivation and writes it
     back, in a single transaction per row.
  5. Reports counts (reencrypted, already_current, failed).

Use cases
---------
- Upgrading from the pre-PBKDF2 (SHA-256) derivation to PBKDF2+Fernet.
- Changing KDF_SALT after a security incident (only works if SECRET_KEY
  is unchanged and you still have the old salt documented).
- Routine hardening pass: confirm the DB only contains ciphertexts
  produced by the current derivation.

Usage
-----
Run as a one-shot CLI:    python3 -m src.migration
Or import and call:       await reencrypt_all()

This is safe to run multiple times — rows that already use the current
derivation are skipped.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from sqlalchemy import select

from src.crypto import decrypt_value, encrypt_value, is_current_derivation
from src.database import async_session, init_db
from src.models import DiscoveredKey

logger = logging.getLogger("verificationrotation")


@dataclass
class MigrationResult:
    total: int = 0
    reencrypted: int = 0
    already_current: int = 0
    failed: int = 0
    errors: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "reencrypted": self.reencrypted,
            "already_current": self.already_current,
            "failed": self.failed,
            "errors": list(self.errors),
        }


async def reencrypt_all() -> MigrationResult:
    """Re-encrypt every DiscoveredKey using the current key derivation.

    Idempotent — running it twice does not double-encrypt or corrupt
    rows. The function returns counters so the caller can log/report.
    """
    result = MigrationResult()

    # Make sure the DB is initialized before we touch it.
    try:
        await init_db()
    except Exception as exc:
        logger.exception("init_db failed during migration: %s", exc)
        result.failed += 1
        result.errors.append(f"init_db failed: {exc}")
        return result

    async with async_session() as session:
        rows = (await session.execute(select(DiscoveredKey))).scalars().all()
        result.total = len(rows)

        for row in rows:
            ciphertext = row.value_encrypted
            if not ciphertext:
                result.failed += 1
                result.errors.append(f"row {row.id}: empty ciphertext")
                continue

            if is_current_derivation(ciphertext):
                result.already_current += 1
                continue

            # Try the legacy derivation (and the current one as a final
            # fallback — decrypt_value already does both, with logging).
            try:
                plaintext = decrypt_value(ciphertext)
            except ValueError as exc:
                result.failed += 1
                result.errors.append(
                    f"row {row.id}: cannot decrypt (SECRET_KEY changed?): {exc}"
                )
                continue
            except Exception as exc:
                result.failed += 1
                result.errors.append(f"row {row.id}: unexpected decrypt error: {exc}")
                continue

            try:
                row.value_encrypted = encrypt_value(plaintext)
            except Exception as exc:
                result.failed += 1
                result.errors.append(f"row {row.id}: re-encrypt failed: {exc}")
                continue

            session.add(row)
            result.reencrypted += 1

        try:
            await session.commit()
        except Exception as exc:
            logger.exception("Migration commit failed: %s", exc)
            result.failed += result.reencrypted
            result.errors.append(f"commit failed (rolled back): {exc}")
            result.reencrypted = 0
            await session.rollback()

    logger.info(
        "Re-encryption migration: %s",
        result.as_dict(),
    )
    return result


def main() -> int:
    """CLI entry point — prints a one-line summary and exits 0/1."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )
    try:
        result = asyncio.run(reencrypt_all())
    except KeyboardInterrupt:
        print("Migration interrupted", flush=True)
        return 130
    except Exception as exc:
        print(f"Migration failed: {type(exc).__name__}: {exc}", flush=True)
        return 1

    summary = (
        f"reencrypted={result.reencrypted} "
        f"already_current={result.already_current} "
        f"failed={result.failed} "
        f"total={result.total}"
    )
    print(summary, flush=True)
    if result.errors:
        print("Errors:", flush=True)
        for err in result.errors:
            print(f"  - {err}", flush=True)
    return 0 if result.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
