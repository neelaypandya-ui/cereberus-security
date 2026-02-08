"""Tests for DataExporter — CSV/JSON export with job status tracking."""

import csv
import json
import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.export.exporter import DataExporter


def _make_alert(alert_id=1, severity="high", module_source="network_sentinel",
                title="Test Alert", description="Something suspicious",
                acknowledged=False, details_json=None, feedback=None):
    """Create a mock Alert ORM object."""
    alert = MagicMock()
    alert.id = alert_id
    alert.timestamp = datetime(2026, 2, 7, 12, 0, 0, tzinfo=timezone.utc)
    alert.severity = severity
    alert.module_source = module_source
    alert.title = title
    alert.description = description
    alert.acknowledged = acknowledged
    alert.resolved_at = None
    alert.feedback = feedback
    alert.details_json = details_json
    return alert


def _make_export_job(job_id=1, export_type="alerts", fmt="csv",
                     filters_json=None, status="pending"):
    """Create a mock ExportJob ORM object."""
    job = MagicMock()
    job.id = job_id
    job.export_type = export_type
    job.format = fmt
    job.filters_json = filters_json
    job.status = status
    job.file_path = None
    job.file_size_bytes = None
    job.completed_at = None
    job.error_message = None
    job.requested_at = datetime(2026, 2, 7, 10, 0, 0, tzinfo=timezone.utc)
    return job


def _make_session_factory(alerts=None, job=None):
    """Build a mock async session factory.

    The factory returns alerts on scalars().all() queries and the job on
    scalar_one_or_none() queries.
    """
    alerts = alerts or []

    session = AsyncMock()

    async def _execute(query):
        result = MagicMock()
        scalars = MagicMock()
        scalars.all.return_value = alerts
        result.scalars.return_value = scalars
        result.scalar_one_or_none = MagicMock(return_value=job)
        return result

    session.execute = AsyncMock(side_effect=_execute)
    session.commit = AsyncMock()

    context = AsyncMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)

    factory = MagicMock(return_value=context)
    return factory, session


class TestExportCSV:
    @pytest.mark.asyncio
    async def test_process_export_csv(self):
        """process_export should create a CSV file with alert data."""
        alert1 = _make_alert(alert_id=1, severity="high", title="Alert One")
        alert2 = _make_alert(alert_id=2, severity="critical", title="Alert Two")

        with tempfile.TemporaryDirectory() as tmpdir:
            job = _make_export_job(
                job_id=1, export_type="alerts", fmt="csv", filters_json=None,
            )
            factory, session = _make_session_factory(alerts=[alert1, alert2], job=job)

            exporter = DataExporter(
                db_session_factory=factory,
                export_dir=tmpdir,
            )

            await exporter.process_export(job_id=1)

            # Verify a CSV file was created in the export dir
            files = os.listdir(tmpdir)
            csv_files = [f for f in files if f.endswith(".csv")]
            assert len(csv_files) == 1

            # Verify CSV content
            csv_path = os.path.join(tmpdir, csv_files[0])
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            assert len(rows) == 2
            assert rows[0]["title"] == "Alert One"
            assert rows[1]["title"] == "Alert Two"


class TestExportJSON:
    @pytest.mark.asyncio
    async def test_process_export_json(self):
        """process_export should create a JSON file with alert data."""
        alert1 = _make_alert(alert_id=1, severity="medium", title="JSON Alert")

        with tempfile.TemporaryDirectory() as tmpdir:
            job = _make_export_job(
                job_id=2, export_type="alerts", fmt="json", filters_json=None,
            )
            factory, session = _make_session_factory(alerts=[alert1], job=job)

            exporter = DataExporter(
                db_session_factory=factory,
                export_dir=tmpdir,
            )

            await exporter.process_export(job_id=2)

            # Verify a JSON file was created
            files = os.listdir(tmpdir)
            json_files = [f for f in files if f.endswith(".json")]
            assert len(json_files) == 1

            # Verify JSON content
            json_path = os.path.join(tmpdir, json_files[0])
            with open(json_path, "r", encoding="utf-8") as f:
                records = json.load(f)
            assert len(records) == 1
            assert records[0]["title"] == "JSON Alert"
            assert records[0]["severity"] == "medium"


class TestExportJobStatus:
    @pytest.mark.asyncio
    async def test_export_job_status_updated(self):
        """process_export should update the job status to 'completed'."""
        alert1 = _make_alert(alert_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            job = _make_export_job(job_id=3, export_type="alerts", fmt="csv")
            factory, session = _make_session_factory(alerts=[alert1], job=job)

            exporter = DataExporter(
                db_session_factory=factory,
                export_dir=tmpdir,
            )

            await exporter.process_export(job_id=3)

            # The job's status should have been set to "completed"
            assert job.status == "completed"
            assert job.file_path is not None
            assert job.completed_at is not None
