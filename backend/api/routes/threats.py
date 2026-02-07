"""Threat Intelligence API routes."""

from fastapi import APIRouter, Depends

from ...dependencies import get_current_user, get_threat_intelligence

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("/level")
async def get_threat_level(current_user: dict = Depends(get_current_user)):
    """Get current overall threat level."""
    ti = get_threat_intelligence()
    return {"threat_level": ti.get_threat_level()}


@router.get("/feed")
async def get_threat_feed(
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
):
    """Get the unified threat event feed."""
    ti = get_threat_intelligence()
    return ti.get_threat_feed(limit)


@router.get("/correlations")
async def get_correlations(current_user: dict = Depends(get_current_user)):
    """Get correlated attack patterns."""
    ti = get_threat_intelligence()
    return ti.get_correlations()
