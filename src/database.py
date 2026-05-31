"""Async database engine and session factory."""

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from src.config import settings

logger = logging.getLogger("verificationrotation")

DATABASE_URL = f"sqlite+aiosqlite:///{settings.data_dir / 'verificationrotation.db'}"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# Columns that may be missing from older databases.
# Format: (table_name, column_name, sql_type)
_MIGRATIONS = [
    ("scan_log", "error_message", "TEXT"),
    ("scan_log", "scan_errors", "TEXT"),
    ("services", "settings_url", "VARCHAR"),
    ("services", "docker_name", "VARCHAR"),
    ("services", "health_url", "VARCHAR"),
    ("services", "detected_config_path", "VARCHAR(512)"),
    ("services", "detected_config_format", "VARCHAR(32)"),
]


def _run_migrations(sync_conn):
    """Add missing columns to existing tables (runs inside run_sync)."""
    from src.models import Base

    try:
        # Ensure all tables exist (creates new ones, silently skips existing)
        Base.metadata.create_all(sync_conn)
    except Exception:
        logger.exception("Failed to create database tables")
        raise

    # Check existing columns and add any that are missing
    try:
        result = sync_conn.execute(text("PRAGMA table_info('scan_log')"))
        scan_log_cols = {row[1] for row in result}
        result = sync_conn.execute(text("PRAGMA table_info('services')"))
        services_cols = {row[1] for row in result}
    except Exception:
        logger.exception("Failed to read database schema — skipping migrations")
        return

    existing = {"scan_log": scan_log_cols, "services": services_cols}

    for table, column, col_type in _MIGRATIONS:
        if table not in existing:
            continue
        if column not in existing[table]:
            try:
                sync_conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                logger.info("Migrated: added %s.%s", table, column)
            except Exception:
                logger.exception("Migration failed: could not add %s.%s", table, column)

    try:
        sync_conn.commit()
    except Exception:
        logger.exception("Failed to commit migrations")


async def init_db():
    """Create tables if they don't exist and apply any missing migrations."""
    async with engine.begin() as conn:
        await conn.run_sync(_run_migrations)