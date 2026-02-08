"""Data exporter — async export of alerts, incidents, audit logs, and IOCs to CSV/JSON."""

import asyncio
import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from ..models.alert import Alert
from ..models.audit_log import AuditLog
from ..models.export_job import ExportJob
from ..models.incident import Incident
from ..models.ioc import IOC
from ..utils.logging import get_logger

logger = get_logger("export.exporter")


class DataExporter:
    """Exports data from the database to CSV or JSON files.

    Each export is tracked via an ExportJob record. The actual export work
    runs as an asyncio background task so API responses return immediately.
    """

    def __init__(self, db_session_factory, export_dir: str = "exports") -> None:
        self._session_factory = db_session_factory
        self._export_dir = export_dir
        self._ensure_export_dir()

    def _ensure_export_dir(self) -> None:
        """Create the export directory if it does not exist."""
        Path(self._export_dir).mkdir(parents=True, exist_ok=True)

    async def process_export(self, job_id: int) -> None:
        """Process an export job: load config, generate file, update status.

        This method is intended to be run as an asyncio background task.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(ExportJob).where(ExportJob.id == job_id)
            )
            job = result.scalar_one_or_none()
            if job is None:
                logger.error("export_job_not_found", job_id=job_id)
                return

            # Mark as processing
            job.status = "processing"
            await session.commit()

        try:
            # Parse filters
            filters = {}
            async with self._session_factory() as session:
                result = await session.execute(
                    select(ExportJob).where(ExportJob.id == job_id)
                )
                job = result.scalar_one_or_none()
                if job.filters_json:
                    try:
                        filters = json.loads(job.filters_json)
                    except json.JSONDecodeError:
                        pass

                export_type = job.export_type
                export_format = job.format

            # Build file path
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"{export_type}_{timestamp_str}.{export_format}"
            file_path = os.path.join(self._export_dir, filename)

            # Dispatch to appropriate export handler
            dispatch_key = f"{export_type}_{export_format}"
            handlers = {
                "alerts_csv": self._export_alerts_csv,
                "alerts_json": self._export_alerts_json,
                "incidents_csv": self._export_incidents_csv,
                "incidents_json": self._export_incidents_json,
                "audit_csv": self._export_audit_csv,
                "audit_json": self._export_audit_json,
                "iocs_csv": self._export_iocs_csv,
                "iocs_json": self._export_iocs_json,
            }

            handler = handlers.get(dispatch_key)
            if handler is None:
                raise ValueError(f"Unsupported export type/format: {dispatch_key}")

            await handler(filters, file_path)

            # Get file size
            file_size = os.path.getsize(file_path)

            # Update job as completed
            async with self._session_factory() as session:
                result = await session.execute(
                    select(ExportJob).where(ExportJob.id == job_id)
                )
                job = result.scalar_one_or_none()
                job.status = "completed"
                job.file_path = file_path
                job.file_size_bytes = file_size
                job.completed_at = datetime.now(timezone.utc)
                await session.commit()

            logger.info(
                "export_completed",
                job_id=job_id,
                export_type=export_type,
                format=export_format,
                file_path=file_path,
                file_size=file_size,
            )

        except Exception as exc:
            logger.error("export_failed", job_id=job_id, error=str(exc))
            async with self._session_factory() as session:
                result = await session.execute(
                    select(ExportJob).where(ExportJob.id == job_id)
                )
                job = result.scalar_one_or_none()
                if job:
                    job.status = "failed"
                    job.error_message = str(exc)
                    job.completed_at = datetime.now(timezone.utc)
                    await session.commit()

    # ── Alert exports ──────────────────────────────────────────────────────

    async def _export_alerts_csv(self, filters: dict, path: str) -> None:
        """Export alerts to a CSV file."""
        async with self._session_factory() as session:
            query = select(Alert).order_by(Alert.timestamp.desc())
            query = self._apply_alert_filters(query, filters)
            result = await session.execute(query)
            alerts = result.scalars().all()

        rows = []
        for a in alerts:
            rows.append({
                "id": a.id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else "",
                "severity": a.severity,
                "module_source": a.module_source,
                "title": a.title,
                "description": a.description,
                "acknowledged": a.acknowledged,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else "",
                "feedback": a.feedback or "",
            })

        self._write_csv(path, rows)

    async def _export_alerts_json(self, filters: dict, path: str) -> None:
        """Export alerts to a JSON file."""
        async with self._session_factory() as session:
            query = select(Alert).order_by(Alert.timestamp.desc())
            query = self._apply_alert_filters(query, filters)
            result = await session.execute(query)
            alerts = result.scalars().all()

        records = []
        for a in alerts:
            records.append({
                "id": a.id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "severity": a.severity,
                "module_source": a.module_source,
                "title": a.title,
                "description": a.description,
                "details": json.loads(a.details_json) if a.details_json else None,
                "acknowledged": a.acknowledged,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                "feedback": a.feedback,
            })

        self._write_json(path, records)

    @staticmethod
    def _apply_alert_filters(query, filters: dict):
        """Apply optional filters to an alert query."""
        if filters.get("severity"):
            query = query.where(Alert.severity == filters["severity"])
        if filters.get("module_source"):
            query = query.where(Alert.module_source == filters["module_source"])
        if filters.get("acknowledged") is not None:
            query = query.where(Alert.acknowledged == filters["acknowledged"])
        return query

    # ── Incident exports ───────────────────────────────────────────────────

    async def _export_incidents_csv(self, filters: dict, path: str) -> None:
        """Export incidents to a CSV file."""
        async with self._session_factory() as session:
            query = select(Incident).order_by(Incident.created_at.desc())
            query = self._apply_incident_filters(query, filters)
            result = await session.execute(query)
            incidents = result.scalars().all()

        rows = []
        for inc in incidents:
            rows.append({
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "category": inc.category or "",
                "assigned_to": inc.assigned_to or "",
                "created_by": inc.created_by or "",
                "created_at": inc.created_at.isoformat() if inc.created_at else "",
                "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else "",
            })

        self._write_csv(path, rows)

    async def _export_incidents_json(self, filters: dict, path: str) -> None:
        """Export incidents to a JSON file."""
        async with self._session_factory() as session:
            query = select(Incident).order_by(Incident.created_at.desc())
            query = self._apply_incident_filters(query, filters)
            result = await session.execute(query)
            incidents = result.scalars().all()

        records = []
        for inc in incidents:
            records.append({
                "id": inc.id,
                "title": inc.title,
                "description": inc.description,
                "severity": inc.severity,
                "status": inc.status,
                "category": inc.category,
                "assigned_to": inc.assigned_to,
                "source_alert_ids": json.loads(inc.source_alert_ids_json) if inc.source_alert_ids_json else None,
                "notes": inc.notes,
                "created_by": inc.created_by,
                "created_at": inc.created_at.isoformat() if inc.created_at else None,
                "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
                "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
            })

        self._write_json(path, records)

    @staticmethod
    def _apply_incident_filters(query, filters: dict):
        """Apply optional filters to an incident query."""
        if filters.get("severity"):
            query = query.where(Incident.severity == filters["severity"])
        if filters.get("status"):
            query = query.where(Incident.status == filters["status"])
        return query

    # ── Audit log exports ──────────────────────────────────────────────────

    async def _export_audit_csv(self, filters: dict, path: str) -> None:
        """Export audit logs to a CSV file."""
        async with self._session_factory() as session:
            query = select(AuditLog).order_by(AuditLog.timestamp.desc())
            query = self._apply_audit_filters(query, filters)
            result = await session.execute(query)
            logs = result.scalars().all()

        rows = []
        for log in logs:
            rows.append({
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else "",
                "username": log.username or "",
                "action": log.action,
                "endpoint": log.endpoint,
                "target": log.target or "",
                "ip_address": log.ip_address or "",
                "status_code": log.status_code or "",
            })

        self._write_csv(path, rows)

    async def _export_audit_json(self, filters: dict, path: str) -> None:
        """Export audit logs to a JSON file."""
        async with self._session_factory() as session:
            query = select(AuditLog).order_by(AuditLog.timestamp.desc())
            query = self._apply_audit_filters(query, filters)
            result = await session.execute(query)
            logs = result.scalars().all()

        records = []
        for log in logs:
            records.append({
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "user_id": log.user_id,
                "username": log.username,
                "action": log.action,
                "endpoint": log.endpoint,
                "target": log.target,
                "details": json.loads(log.details_json) if log.details_json else None,
                "ip_address": log.ip_address,
                "status_code": log.status_code,
            })

        self._write_json(path, records)

    @staticmethod
    def _apply_audit_filters(query, filters: dict):
        """Apply optional filters to an audit log query."""
        if filters.get("action"):
            query = query.where(AuditLog.action == filters["action"])
        if filters.get("username"):
            query = query.where(AuditLog.username == filters["username"])
        return query

    # ── IOC exports ────────────────────────────────────────────────────────

    async def _export_iocs_csv(self, filters: dict, path: str) -> None:
        """Export IOCs to a CSV file."""
        async with self._session_factory() as session:
            query = select(IOC).order_by(IOC.first_seen.desc())
            query = self._apply_ioc_filters(query, filters)
            result = await session.execute(query)
            iocs = result.scalars().all()

        rows = []
        for ioc in iocs:
            rows.append({
                "id": ioc.id,
                "ioc_type": ioc.ioc_type,
                "value": ioc.value,
                "severity": ioc.severity,
                "source": ioc.source or "",
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else "",
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else "",
                "active": ioc.active,
                "feed_id": ioc.feed_id or "",
            })

        self._write_csv(path, rows)

    async def _export_iocs_json(self, filters: dict, path: str) -> None:
        """Export IOCs to a JSON file."""
        async with self._session_factory() as session:
            query = select(IOC).order_by(IOC.first_seen.desc())
            query = self._apply_ioc_filters(query, filters)
            result = await session.execute(query)
            iocs = result.scalars().all()

        records = []
        for ioc in iocs:
            records.append({
                "id": ioc.id,
                "ioc_type": ioc.ioc_type,
                "value": ioc.value,
                "severity": ioc.severity,
                "source": ioc.source,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                "tags": json.loads(ioc.tags_json) if ioc.tags_json else None,
                "context": json.loads(ioc.context_json) if ioc.context_json else None,
                "active": ioc.active,
                "feed_id": ioc.feed_id,
            })

        self._write_json(path, records)

    @staticmethod
    def _apply_ioc_filters(query, filters: dict):
        """Apply optional filters to an IOC query."""
        if filters.get("ioc_type"):
            query = query.where(IOC.ioc_type == filters["ioc_type"])
        if filters.get("severity"):
            query = query.where(IOC.severity == filters["severity"])
        if filters.get("source"):
            query = query.where(IOC.source == filters["source"])
        if filters.get("active") is not None:
            query = query.where(IOC.active == filters["active"])
        return query

    # ── File writing helpers ───────────────────────────────────────────────

    @staticmethod
    def _write_csv(path: str, rows: list[dict]) -> None:
        """Write a list of dictionaries to a CSV file."""
        if not rows:
            # Write empty CSV with no rows
            with open(path, "w", newline="", encoding="utf-8") as f:
                f.write("")
            return

        fieldnames = list(rows[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def _write_json(path: str, records: list[dict]) -> None:
        """Write a list of dictionaries to a JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, default=str)
