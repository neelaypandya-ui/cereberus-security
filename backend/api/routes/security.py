"""Brute Force Shield routes."""

from fastapi import APIRouter, Depends, Query

from ...auth.rbac import require_permission, PERM_MANAGE_SETTINGS, PERM_VIEW_DASHBOARD
from ...dependencies import get_brute_force_shield

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/brute-force/events")
async def get_brute_force_events(
    limit: int = Query(50, ge=1, le=500),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get recent brute-force events."""
    shield = get_brute_force_shield()
    return shield.get_recent_events(limit=limit)


@router.get("/brute-force/blocked")
async def get_blocked_ips(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get currently blocked IPs."""
    shield = get_brute_force_shield()
    return shield.get_blocked_ips()


@router.post("/brute-force/unblock/{ip}")
async def unblock_ip(
    ip: str,
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Manually unblock an IP address."""
    shield = get_brute_force_shield()
    return await shield.unblock_ip(ip)
