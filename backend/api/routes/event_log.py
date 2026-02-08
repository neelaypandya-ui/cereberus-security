"""Event Log Monitor API routes."""

from fastapi import APIRouter, Depends, Query

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD
from ...dependencies import get_event_log_monitor

router = APIRouter(prefix="/event-log", tags=["event-log"])


@router.get("/")
async def get_events(
    limit: int = Query(100, ge=1, le=500),
    event_type: int | None = Query(None, description="Filter by Windows Event ID"),
    severity: str | None = Query(
        None,
        description="Filter by severity level",
        pattern="^(critical|high|medium|low)$",
    ),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get recent Windows Event Log entries.

    Supports filtering by event type (Windows Event ID) and severity level.
    Results are returned newest first.
    """
    monitor = get_event_log_monitor()

    if event_type is not None:
        return monitor.get_events_by_type(event_type, limit=limit)

    if severity is not None:
        return monitor.get_events_by_severity(severity, limit=limit)

    return monitor.get_events(limit=limit)


@router.get("/stats")
async def get_event_stats(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get event collection statistics by type and severity."""
    monitor = get_event_log_monitor()
    return monitor.get_stats()


@router.get("/critical")
async def get_critical_events(
    limit: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get recent critical and high severity events."""
    monitor = get_event_log_monitor()
    return monitor.get_recent_critical(limit=limit)
