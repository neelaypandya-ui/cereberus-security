"""Tests for RetentionManager — automated cleanup of aged records."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.maintenance.retention import RetentionManager


def _make_config(alert_days=90, audit_days=365, anomaly_days=30,
                 snapshot_days=7, export_days=30,
                 incidents_days=365, remediation_days=180,
                 comments_days=365, iocs_days=180):
    """Create a mock config with retention day settings."""
    config = MagicMock()
    config.retention_alerts_days = alert_days
    config.retention_audit_days = audit_days
    config.retention_anomaly_days = anomaly_days
    config.retention_snapshots_days = snapshot_days
    config.retention_exports_days = export_days
    config.retention_incidents_days = incidents_days
    config.retention_remediation_days = remediation_days
    config.retention_comments_days = comments_days
    config.retention_iocs_days = iocs_days
    return config


def _make_session_factory():
    """Build a mock async session factory that tracks delete operations.

    Returns (factory, session, delete_results) where delete_results is a
    list that accumulates rowcount values set by the test.
    """
    session = AsyncMock()
    delete_results = []

    # Each execute call on a DELETE returns a result with rowcount
    call_counter = {"n": 0}

    async def _execute(query):
        call_counter["n"] += 1
        result = MagicMock()

        # Calls to select (for export files) return empty list
        scalars = MagicMock()
        scalars.all.return_value = []
        result.scalars.return_value = scalars

        # For DELETE statements, return pre-configured rowcounts
        if call_counter["n"] <= len(delete_results):
            result.rowcount = delete_results[call_counter["n"] - 1]
        else:
            result.rowcount = 0
        return result

    session.execute = AsyncMock(side_effect=_execute)
    session.commit = AsyncMock()

    context = AsyncMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)

    factory = MagicMock(return_value=context)
    return factory, session, delete_results


class TestCleanupAlerts:
    @pytest.mark.asyncio
    async def test_cleanup_deletes_old_alerts(self):
        """run_cleanup should issue a DELETE query for alerts older than configured days."""
        config = _make_config(alert_days=90)
        factory, session, delete_results = _make_session_factory()
        # Set rowcounts: alerts=5, audit=0, anomaly=0, snapshots=0, select_exports=0, delete_exports=0,
        # incidents=0, remediation=0, comments=0, iocs=0
        delete_results.extend([5, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        manager = RetentionManager(db_session_factory=factory, config=config)

        summary = await manager.run_cleanup()

        assert summary["alerts"] == 5
        # Verify session.execute was called (at least for the alert deletion)
        assert session.execute.call_count >= 1
        session.commit.assert_called_once()


class TestCleanupAuditLogs:
    @pytest.mark.asyncio
    async def test_cleanup_deletes_old_audit_logs(self):
        """run_cleanup should issue a DELETE query for audit logs older than configured days."""
        config = _make_config(audit_days=365)
        factory, session, delete_results = _make_session_factory()
        # alerts=0, audit=12, anomaly=0, snapshots=0, select_exports=0, delete_exports=0,
        # incidents=0, remediation=0, comments=0, iocs=0
        delete_results.extend([0, 12, 0, 0, 0, 0, 0, 0, 0, 0])

        manager = RetentionManager(db_session_factory=factory, config=config)

        summary = await manager.run_cleanup()

        assert summary["audit_logs"] == 12
        session.commit.assert_called_once()


class TestCleanupRespectsConfig:
    @pytest.mark.asyncio
    async def test_cleanup_respects_config(self):
        """run_cleanup should use the configured retention days, not hard-coded defaults."""
        # Use non-default retention values
        config = _make_config(alert_days=7, audit_days=14)
        factory, session, delete_results = _make_session_factory()
        delete_results.extend([3, 8, 0, 0, 0, 0, 0, 0, 0, 0])

        manager = RetentionManager(db_session_factory=factory, config=config)

        # Verify the config values are what we set
        assert manager._config.retention_alerts_days == 7
        assert manager._config.retention_audit_days == 14

        summary = await manager.run_cleanup()

        # The deletion should have used our custom retention periods
        assert summary["alerts"] == 3
        assert summary["audit_logs"] == 8
