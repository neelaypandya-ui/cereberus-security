"""File Integrity Monitor routes."""

from fastapi import APIRouter, Depends

from ...dependencies import get_current_user, get_file_integrity

router = APIRouter(prefix="/integrity", tags=["integrity"])


@router.get("/baselines")
async def get_baselines(
    current_user: dict = Depends(get_current_user),
):
    """Get the current file integrity baseline."""
    fi = get_file_integrity()
    return fi.get_baselines()


@router.post("/scan")
async def trigger_scan(
    current_user: dict = Depends(get_current_user),
):
    """Trigger a manual file integrity scan."""
    fi = get_file_integrity()
    return await fi.run_scan()


@router.get("/changes")
async def get_changes(
    current_user: dict = Depends(get_current_user),
):
    """Get the results of the last integrity scan."""
    fi = get_file_integrity()
    result = fi.get_last_scan()
    if result is None:
        return {"message": "No scan has been run yet"}
    return result
