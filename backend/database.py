"""Database engine, session management, and table creation."""

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import CereberusConfig
from .models.base import Base

logger = logging.getLogger("cereberus.database")

_engine = None
_session_factory = None


def get_engine(config: CereberusConfig):
    """Get or create the async database engine."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            config.database_url,
            echo=config.debug,
            future=True,
            pool_pre_ping=True,
            connect_args={"timeout": 30},
        )
    return _engine


def get_session_factory(config: CereberusConfig) -> async_sessionmaker[AsyncSession]:
    """Get or create the async session factory."""
    global _session_factory
    if _session_factory is None:
        engine = get_engine(config)
        _session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return _session_factory


async def _enable_wal_mode(config: CereberusConfig) -> None:
    """Enable WAL journal mode and performance PRAGMAs for SQLite."""
    if not config.db_wal_mode:
        return
    engine = get_engine(config)
    async with engine.begin() as conn:
        await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.execute(text(f"PRAGMA busy_timeout={config.db_busy_timeout}"))
        await conn.execute(text(f"PRAGMA synchronous={config.db_synchronous}"))
    logger.info(
        "SQLite PRAGMAs applied: WAL mode, busy_timeout=%d, synchronous=%s",
        config.db_busy_timeout,
        config.db_synchronous,
    )


async def create_tables(config: CereberusConfig) -> None:
    """Create all database tables and apply performance PRAGMAs."""
    engine = get_engine(config)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await _enable_wal_mode(config)


async def get_session(config: CereberusConfig) -> AsyncSession:
    """Get a new async session."""
    factory = get_session_factory(config)
    async with factory() as session:
        yield session


async def close_engine() -> None:
    """Close the database engine."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
