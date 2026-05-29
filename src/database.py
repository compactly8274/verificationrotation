"""Async database engine and session factory."""

import logging

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from src.config import settings

logger = logging.getLogger("verificationrotation")

DATABASE_URL = f"sqlite+aiosqlite:///{settings.data_dir / 'verificationrotation.db'}"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def _migrate(conn):
    """Add missing columns and tables that were introduced after the initial schema."""
    from src.models import Base

    # Ensure all new tables exist
    await conn.run_sync(Base.metadata.create_all)

    # Add columns that may be missing from older databases
    inspector = inspect(conn.sync_connection)
    migrations = [
        ("scan_log", "error_message", "TEXT"),
        ("scan_log", "scan_errors", "TEXT"),
        ("services", "settings_url", "VARCHAR"),
        ("services", "docker_name", "VARCHAR"),
        ("services", "health_url", "VARCHAR"),
    ]
    for table, column, col_type in migrations:
        if table not in inspector.get_table_names():
            continue
        existing = {c["name"] for c in inspector.get_columns(table)}
        if column not in existing:
            await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
            logger.info("Migrated: added %s.%s", table, column)


async def init_db():
    """Create tables if they don't exist and apply any missing migrations."""
    async with engine.begin() as conn:
        await _migrate(conn)
