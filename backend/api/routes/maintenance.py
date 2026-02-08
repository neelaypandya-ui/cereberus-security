"""Maintenance routes — database backup, restore, and data retention."""

from fastapi import APIRouter, Depends, HTTPException

from ...auth.rbac import require_permission, PERM_MANAGE_SETTINGS
from ...dependencies import get_app_config
from ...database import get_session_factory

router = APIRouter(prefix="/maintenance", tags=["maintenance"])

_retention_manager = None
_backup_manager = None


def _get_backup_manager():
    """Get or create the BackupManager singleton."""
    from ...maintenance.backup import BackupManager

    global _backup_manager
    if _backup_manager is None:
        _backup_manager = BackupManager()
    return _backup_manager


def _get_retention_manager():
    """Get or create the RetentionManager singleton."""
    from ...maintenance.retention import RetentionManager

    global _retention_manager
    if _retention_manager is None:
        config = get_app_config()
        factory = get_session_factory(config)
        _retention_manager = RetentionManager(
            db_session_factory=factory,
            config=config,
        )
    return _retention_manager


@router.post("/backup")
async def trigger_backup(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Trigger a database backup (admin only)."""
    manager = _get_backup_manager()
    try:
        result = manager.backup_database()
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "status": "backup_created",
        "path": result["path"],
        "size": result["size"],
        "timestamp": result["timestamp"],
    }


@router.get("/backups")
async def list_backups(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """List available database backups (admin only)."""
    manager = _get_backup_manager()
    backups = manager.list_backups()
    return {"backups": backups, "count": len(backups)}


@router.post("/cleanup")
async def trigger_cleanup(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Trigger data retention cleanup (admin only)."""
    manager = _get_retention_manager()
    summary = await manager.run_cleanup()
    return {"status": "cleanup_complete", "summary": summary}


@router.get("/retention")
async def get_retention_config(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Get current retention configuration (admin only)."""
    config = get_app_config()
    return {
        "retention_alerts_days": config.retention_alerts_days,
        "retention_audit_days": config.retention_audit_days,
        "retention_anomaly_days": config.retention_anomaly_days,
        "retention_snapshots_days": config.retention_snapshots_days,
        "retention_exports_days": config.retention_exports_days,
        "retention_cleanup_interval_hours": config.retention_cleanup_interval_hours,
    }
