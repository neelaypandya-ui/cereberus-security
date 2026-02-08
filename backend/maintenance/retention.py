"""Data retention manager — automated cleanup of aged records."""

import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..utils.logging import get_logger

logger = get_logger("maintenance.retention")


class RetentionManager:
    """Manages data retention by deleting records older than configured thresholds."""

    def __init__(
        self,
        db_session_factory: async_sessionmaker[AsyncSession],
        config,
    ):
        self._session_factory = db_session_factory
        self._config = config

    async def run_cleanup(self) -> dict:
        """Run retention cleanup across all configured tables.

        Returns a summary dict with counts of deleted records per table.
        """
        summary = {}
        now = datetime.now(timezone.utc)

        async with self._session_factory() as session:
            # --- Alerts ---
            retention_days = getattr(self._config, "retention_alerts_days", 90)
            cutoff = now - timedelta(days=retention_days)
            from ..models.alert import Alert

            result = await session.execute(
                delete(Alert).where(Alert.timestamp < cutoff)
            )
            summary["alerts"] = result.rowcount
            logger.info(
                "retention_cleanup",
                table="alerts",
                deleted=result.rowcount,
                cutoff_days=retention_days,
            )

            # --- Audit Logs ---
            retention_days = getattr(self._config, "retention_audit_days", 365)
            cutoff = now - timedelta(days=retention_days)
            from ..models.audit_log import AuditLog

            result = await session.execute(
                delete(AuditLog).where(AuditLog.timestamp < cutoff)
            )
            summary["audit_logs"] = result.rowcount
            logger.info(
                "retention_cleanup",
                table="audit_logs",
                deleted=result.rowcount,
                cutoff_days=retention_days,
            )

            # --- Anomaly Events ---
            retention_days = getattr(self._config, "retention_anomaly_days", 30)
            cutoff = now - timedelta(days=retention_days)
            from ..models.anomaly_event import AnomalyEvent

            result = await session.execute(
                delete(AnomalyEvent).where(AnomalyEvent.timestamp < cutoff)
            )
            summary["anomaly_events"] = result.rowcount
            logger.info(
                "retention_cleanup",
                table="anomaly_events",
                deleted=result.rowcount,
                cutoff_days=retention_days,
            )

            # --- Resource Snapshots ---
            retention_days = getattr(self._config, "retention_snapshots_days", 7)
            cutoff = now - timedelta(days=retention_days)
            from ..models.resource_snapshot import ResourceSnapshot

            result = await session.execute(
                delete(ResourceSnapshot).where(ResourceSnapshot.timestamp < cutoff)
            )
            summary["resource_snapshots"] = result.rowcount
            logger.info(
                "retention_cleanup",
                table="resource_snapshots",
                deleted=result.rowcount,
                cutoff_days=retention_days,
            )

            # --- Export Jobs ---
            retention_days = getattr(self._config, "retention_exports_days", 30)
            cutoff = now - timedelta(days=retention_days)
            from ..models.export_job import ExportJob

            # First, collect file paths of expired exports to delete files
            from sqlalchemy import select

            expired_exports = (
                await session.execute(
                    select(ExportJob).where(ExportJob.requested_at < cutoff)
                )
            ).scalars().all()

            files_deleted = 0
            for export in expired_exports:
                if export.file_path and os.path.exists(export.file_path):
                    try:
                        os.remove(export.file_path)
                        files_deleted += 1
                    except OSError as e:
                        logger.warning(
                            "retention_file_delete_failed",
                            file_path=export.file_path,
                            error=str(e),
                        )

            result = await session.execute(
                delete(ExportJob).where(ExportJob.requested_at < cutoff)
            )
            summary["export_jobs"] = result.rowcount
            summary["export_files_deleted"] = files_deleted
            logger.info(
                "retention_cleanup",
                table="export_jobs",
                deleted=result.rowcount,
                files_deleted=files_deleted,
                cutoff_days=retention_days,
            )

            await session.commit()

        logger.info("retention_cleanup_complete", summary=summary)
        return summary
