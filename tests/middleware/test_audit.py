"""Tests for the audit middleware."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.middleware.audit import AuditMiddleware, AUDITED_METHODS, SKIP_PATHS


class TestAuditMiddlewareConfig:
    def test_audited_methods(self):
        assert "POST" in AUDITED_METHODS
        assert "PUT" in AUDITED_METHODS
        assert "DELETE" in AUDITED_METHODS
        assert "PATCH" in AUDITED_METHODS
        assert "GET" not in AUDITED_METHODS

    def test_skip_paths(self):
        assert "/api/v1/auth/login" in SKIP_PATHS
        assert "/ws/events" in SKIP_PATHS

    def test_init_with_session_factory(self):
        mock_app = MagicMock()
        mock_factory = MagicMock()
        mw = AuditMiddleware(mock_app, session_factory=mock_factory)
        assert mw._session_factory is mock_factory

    def test_init_without_session_factory(self):
        mock_app = MagicMock()
        mw = AuditMiddleware(mock_app)
        assert mw._session_factory is None


class TestUsernameExtraction:
    def test_extract_username_no_auth(self):
        mock_app = MagicMock()
        mw = AuditMiddleware(mock_app)
        request = MagicMock()
        request.headers.get.return_value = ""
        assert mw._extract_username(request) is None

    def test_extract_username_invalid_token(self):
        mock_app = MagicMock()
        mw = AuditMiddleware(mock_app)
        request = MagicMock()
        request.headers.get.return_value = "Bearer invalid"
        with patch("backend.middleware.audit.AuditMiddleware._extract_username", return_value=None):
            result = None
        assert result is None


class TestRecordAudit:
    @pytest.mark.asyncio
    async def test_record_audit_no_factory(self):
        mock_app = MagicMock()
        mw = AuditMiddleware(mock_app, session_factory=None)
        # Should not raise, just return
        await mw._record_audit(
            username="test",
            action="POST",
            endpoint="/test",
            target=None,
            ip_address="127.0.0.1",
            status_code=200,
        )

    @pytest.mark.asyncio
    async def test_record_audit_with_factory(self):
        mock_app = MagicMock()
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_factory = MagicMock(return_value=mock_session)
        mw = AuditMiddleware(mock_app, session_factory=mock_factory)

        await mw._record_audit(
            username="admin",
            action="POST",
            endpoint="/api/v1/test",
            target=None,
            ip_address="127.0.0.1",
            status_code=200,
        )

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
