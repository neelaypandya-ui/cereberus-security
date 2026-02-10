"""Network monitoring routes."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD
from ...bridge import validate_and_log, NetworkConnectionResponse
from ...dependencies import get_db, get_network_sentinel
from ...models.blocked_ip import BlockedIP
from ...models.settings import NetworkTraffic

router = APIRouter(prefix="/network", tags=["network"])


@router.get("/traffic")
async def get_traffic(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    flagged_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get recent network traffic entries."""
    query = select(NetworkTraffic).order_by(NetworkTraffic.timestamp.desc()).limit(limit).offset(offset)
    if flagged_only:
        query = query.where(NetworkTraffic.flagged == True)
    result = await db.execute(query)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "src_port": r.src_port,
            "dst_port": r.dst_port,
            "protocol": r.protocol,
            "bytes_sent": r.bytes_sent,
            "bytes_recv": r.bytes_recv,
            "vpn_routed": r.vpn_routed,
            "geo_country": r.geo_country,
            "flagged": r.flagged,
        }
        for r in rows
    ]


@router.get("/blocked-ips")
async def get_blocked_ips(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get blocked IP addresses with pagination."""
    result = await db.execute(
        select(BlockedIP).order_by(BlockedIP.blocked_at.desc()).limit(limit).offset(offset)
    )
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "reason": r.reason,
            "module_source": r.module_source,
            "blocked_at": r.blocked_at.isoformat(),
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "permanent": r.permanent,
        }
        for r in rows
    ]


@router.get("/connections")
async def get_connections(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get live network connections from Network Sentinel."""
    sentinel = get_network_sentinel()
    return validate_and_log(sentinel.get_live_connections(), NetworkConnectionResponse, "GET /network/connections")


@router.get("/stats")
async def get_network_stats(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get network connection statistics."""
    sentinel = get_network_sentinel()
    return sentinel.get_stats()


@router.get("/flagged")
async def get_flagged_connections(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get flagged (suspicious) connections."""
    sentinel = get_network_sentinel()
    return validate_and_log(sentinel.get_flagged_connections(), NetworkConnectionResponse, "GET /network/flagged")


@router.get("/anomaly")
async def get_anomaly_result(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get the most recent anomaly detection result."""
    sentinel = get_network_sentinel()
    result = sentinel.get_anomaly_result()
    return result or {"anomaly_score": 0, "is_anomaly": False, "threshold": 0.5}


@router.get("/anomaly/history")
async def get_anomaly_history(
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get anomaly event history (only anomalous events)."""
    sentinel = get_network_sentinel()
    return sentinel.get_anomaly_events(limit=limit)


@router.get("/beaconing")
async def get_beaconing(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get detected C2 beaconing patterns."""
    sentinel = get_network_sentinel()
    return sentinel.get_detected_beacons()


@router.get("/connection-history")
async def get_connection_history(
    limit: int = Query(200, ge=1, le=1000),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get recent connection log for beaconing analysis."""
    sentinel = get_network_sentinel()
    return sentinel.get_connection_history(limit=limit)
