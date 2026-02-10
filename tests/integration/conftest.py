"""Integration test fixtures — in-memory app, async client, admin auth."""

import json
import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

# Force test config BEFORE any app imports
os.environ["DEBUG"] = "true"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SECRET_KEY"] = "test-secret-key-for-integration-tests"

import backend.database as db_mod
import backend.dependencies as dep_mod


def _reset_singletons():
    """Reset all module-level singletons so each test session starts clean."""
    db_mod._engine = None
    db_mod._session_factory = None
    dep_mod._config_instance = None
    dep_mod._alert_manager = None
    dep_mod._vpn_guardian = None
    dep_mod._network_sentinel = None
    dep_mod._brute_force_shield = None
    dep_mod._file_integrity = None
    dep_mod._process_analyzer = None
    dep_mod._vuln_scanner = None
    dep_mod._threat_intelligence = None
    dep_mod._resource_monitor = None
    dep_mod._persistence_scanner = None
    dep_mod._anomaly_detector = None
    dep_mod._threat_correlator = None
    dep_mod._ensemble_detector = None
    dep_mod._behavioral_baseline = None
    dep_mod._remediation_engine = None
    dep_mod._incident_manager = None
    dep_mod._playbook_executor = None
    dep_mod._feed_manager = None
    dep_mod._ioc_matcher = None
    dep_mod._notification_dispatcher = None
    dep_mod._data_exporter = None
    dep_mod._event_log_monitor = None
    dep_mod._rule_engine = None
    dep_mod._ransomware_detector = None
    dep_mod._commander_bond = None
    dep_mod._yara_scanner = None
    dep_mod._memory_scanner = None
    dep_mod._event_bus = None


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def test_app():
    """Create test app with in-memory database (shared via StaticPool)."""
    _reset_singletons()

    # Create a shared in-memory engine using StaticPool
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    # Inject into database module BEFORE app import
    db_mod._engine = engine
    factory = async_sessionmaker(engine, expire_on_commit=False)
    db_mod._session_factory = factory

    # Force config singleton
    dep_mod.get_app_config()

    # Import app
    from backend.models.base import Base
    from backend.main import app

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed admin user
    from backend.models.user import User
    from backend.utils.security import hash_password

    async with factory() as session:
        admin = User(
            username="admin",
            password_hash=hash_password("admin"),
            role="admin",
        )
        session.add(admin)
        await session.commit()

    # Seed default roles and assign admin role
    try:
        from backend.models.role import Role
        from backend.auth.rbac import DEFAULT_ROLES
        from backend.models.user_role import UserRole

        async with factory() as session:
            for role_name, role_def in DEFAULT_ROLES.items():
                role = Role(
                    name=role_name,
                    description=role_def["description"],
                    permissions_json=json.dumps(role_def["permissions"]),
                )
                session.add(role)
            await session.commit()

        async with factory() as session:
            result = await session.execute(select(User).where(User.username == "admin"))
            admin_user = result.scalar_one()
            result = await session.execute(select(Role).where(Role.name == "admin"))
            admin_role = result.scalar_one()
            session.add(UserRole(user_id=admin_user.id, role_id=admin_role.id))
            await session.commit()
    except Exception:
        pass

    yield app

    await engine.dispose()
    _reset_singletons()


@pytest_asyncio.fixture(loop_scope="session")
async def client(test_app):
    """Async HTTP client for testing."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture(loop_scope="session")
async def admin_headers(client):
    """Get auth headers for the admin user."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
