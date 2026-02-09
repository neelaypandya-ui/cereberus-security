"""Threat Intelligence API routes."""

from fastapi import APIRouter, Depends, Query

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD
from ...dependencies import get_threat_intelligence

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("/level")
async def get_threat_level(current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD))):
    """Get current overall threat level."""
    ti = get_threat_intelligence()
    return {"threat_level": ti.get_threat_level()}


@router.get("/feed")
async def get_threat_feed(
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get the unified threat event feed."""
    ti = get_threat_intelligence()
    return ti.get_threat_feed(limit)


@router.get("/correlations")
async def get_correlations(current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD))):
    """Get correlated attack patterns."""
    ti = get_threat_intelligence()
    return ti.get_correlations()


@router.get("/timeline")
async def get_threat_timeline(
    lookback_minutes: int = Query(60, ge=1, le=1440),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get chronological threat event timeline."""
    ti = get_threat_intelligence()
    correlator = ti._correlator
    timeline = correlator.build_incident_timeline("", lookback_minutes)
    return {"timeline": timeline, "lookback_minutes": lookback_minutes}


@router.get("/event-chain/{event_type}")
async def get_event_chain(
    event_type: str,
    lookback_minutes: int = Query(30, ge=1, le=1440),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get events of a specific type within lookback window."""
    ti = get_threat_intelligence()
    correlator = ti._correlator
    chain = correlator.get_event_chain(event_type, lookback_minutes)
    return {"event_type": event_type, "events": chain}


@router.get("/pattern-stats")
async def get_pattern_stats(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get pattern match frequencies."""
    ti = get_threat_intelligence()
    correlator = ti._correlator
    stats = correlator.get_pattern_frequency()
    return {"patterns": stats}
