"""Ransomware detector routes."""

from fastapi import APIRouter, Depends

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD
from ...dependencies import get_ransomware_detector

router = APIRouter(prefix="/ransomware", tags=["ransomware"])


@router.get("/status")
async def get_ransomware_status(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get ransomware detector module status and canary health."""
    detector = get_ransomware_detector()
    return detector.get_status()


@router.get("/canaries")
async def get_canaries(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all canary files and their health status."""
    detector = get_ransomware_detector()
    return detector.get_canaries()


@router.get("/detections")
async def get_detections(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get recent ransomware detection events."""
    detector = get_ransomware_detector()
    return detector.get_detections()
