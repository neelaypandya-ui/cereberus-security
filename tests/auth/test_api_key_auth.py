"""Tests for API key authentication — validation, expiry, and revocation."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.dependencies import _validate_api_key


def _make_api_key_record(key_hash, user_id=1, revoked=False, expires_at=None,
                         permissions_json=None, last_used=None):
    """Create a mock APIKey ORM object."""
    record = MagicMock()
    record.key_hash = key_hash
    record.user_id = user_id
    record.revoked = revoked
    record.expires_at = expires_at
    record.last_used = last_used
    record.permissions_json = permissions_json
    return record


def _make_user(user_id=1, username="api_user", role="analyst"):
    """Create a mock User ORM object."""
    user = MagicMock()
    user.id = user_id
    user.username = username
    user.role = role
    return user


def _make_config():
    """Create a mock CereberusConfig."""
    config = MagicMock()
    config.database_url = "sqlite+aiosqlite:///test.db"
    config.secret_key = "test-secret"
    return config


def _build_mock_session(api_key_record, user):
    """Build a mock session factory that returns the given api_key and user."""
    call_counter = {"n": 0}

    session = AsyncMock()

    async def _execute(query):
        call_counter["n"] += 1
        result = MagicMock()
        if call_counter["n"] == 1:
            # First query: look up APIKey by hash
            result.scalar_one_or_none = MagicMock(return_value=api_key_record)
        else:
            # Second query: look up User by ID
            result.scalar_one_or_none = MagicMock(return_value=user)
        return result

    session.execute = AsyncMock(side_effect=_execute)
    session.commit = AsyncMock()

    context = AsyncMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)

    factory = MagicMock(return_value=context)
    return factory


class TestValidAPIKey:
    @pytest.mark.asyncio
    async def test_valid_api_key_authenticates(self):
        """A valid, non-expired, non-revoked API key should return user info."""
        raw_key = "ck_test123456789abcdef"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        api_key_record = _make_api_key_record(
            key_hash=key_hash,
            user_id=1,
            revoked=False,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            permissions_json=json.dumps(["view_dashboard", "manage_alerts"]),
        )
        user = _make_user(user_id=1, username="api_user", role="analyst")
        factory = _build_mock_session(api_key_record, user)
        config = _make_config()

        with patch("backend.dependencies.get_session_factory", return_value=factory):
            result = await _validate_api_key(raw_key, config)

        assert result is not None
        assert result["sub"] == "api_user"
        assert result["role"] == "analyst"
        assert result["auth_method"] == "api_key"
        assert "view_dashboard" in result["permissions"]


class TestExpiredAPIKey:
    @pytest.mark.asyncio
    async def test_expired_api_key_rejected(self):
        """An expired API key should return None (rejected)."""
        raw_key = "ck_expired_key_12345"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        api_key_record = _make_api_key_record(
            key_hash=key_hash,
            user_id=1,
            revoked=False,
            # Expired yesterday
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        user = _make_user(user_id=1, username="api_user")
        factory = _build_mock_session(api_key_record, user)
        config = _make_config()

        with patch("backend.dependencies.get_session_factory", return_value=factory):
            result = await _validate_api_key(raw_key, config)

        assert result is None


class TestRevokedAPIKey:
    @pytest.mark.asyncio
    async def test_revoked_api_key_rejected(self):
        """A revoked API key should return None (rejected).

        Since _validate_api_key queries with APIKey.revoked == False,
        a revoked key will not be found and scalar_one_or_none returns None.
        """
        raw_key = "ck_revoked_key_xyz"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        # Simulate: the query filters out revoked keys, so no record is returned
        session = AsyncMock()

        async def _execute(query):
            result = MagicMock()
            result.scalar_one_or_none = MagicMock(return_value=None)
            return result

        session.execute = AsyncMock(side_effect=_execute)
        session.commit = AsyncMock()

        context = AsyncMock()
        context.__aenter__ = AsyncMock(return_value=session)
        context.__aexit__ = AsyncMock(return_value=False)

        factory = MagicMock(return_value=context)
        config = _make_config()

        with patch("backend.dependencies.get_session_factory", return_value=factory):
            result = await _validate_api_key(raw_key, config)

        assert result is None
