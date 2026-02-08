"""System resource monitoring routes."""

from fastapi import APIRouter, Depends, Query

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD
from ...dependencies import get_resource_monitor

router = APIRouter(prefix="/resources", tags=["resources"])


@router.get("/current")
async def get_resource_current(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get current system resource snapshot."""
    monitor = get_resource_monitor()
    return monitor.get_current()


@router.get("/history")
async def get_resource_history(
    limit: int = Query(60, ge=1, le=360),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get resource snapshot history."""
    monitor = get_resource_monitor()
    return monitor.get_history(limit=limit)


@router.get("/alerts")
async def get_resource_alerts(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get resource threshold alerts."""
    monitor = get_resource_monitor()
    return monitor.get_alerts()
