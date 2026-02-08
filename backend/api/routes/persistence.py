"""Persistence scanner routes."""

from fastapi import APIRouter, Depends

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD
from ...dependencies import get_persistence_scanner

router = APIRouter(prefix="/persistence", tags=["persistence"])


@router.get("/entries")
async def get_persistence_entries(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get all persistence mechanism entries."""
    scanner = get_persistence_scanner()
    return scanner.get_entries()


@router.get("/changes")
async def get_persistence_changes(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get detected changes since baseline."""
    scanner = get_persistence_scanner()
    return scanner.get_changes()


@router.post("/scan")
async def trigger_persistence_scan(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Trigger an immediate persistence scan."""
    scanner = get_persistence_scanner()
    result = await scanner.run_scan()
    return result


@router.get("/status")
async def get_persistence_status(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get persistence scanner status."""
    scanner = get_persistence_scanner()
    return scanner.get_last_scan() or {"baseline_established": False, "entry_count": 0}
