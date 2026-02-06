"""Database engine, session management, and table creation."""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import CereberusConfig
from .models.base import Base

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
        )
    return _engine


def get_session_factory(config: CereberusConfig) -> async_sessionmaker[AsyncSession]:
    """Get or create the async session factory."""
    global _session_factory
    if _session_factory is None:
        engine = get_engine(config)
        _session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return _session_factory


async def create_tables(config: CereberusConfig) -> None:
    """Create all database tables."""
    engine = get_engine(config)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


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
