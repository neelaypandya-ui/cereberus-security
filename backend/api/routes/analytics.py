"""Analytics routes — historical data aggregations for charts."""

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...dependencies import get_current_user, get_db
from ...models.alert import Alert

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/alert-trend")
async def get_alert_trend(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get hourly alert counts for the given time window."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    result = await db.execute(
        select(Alert).where(Alert.timestamp >= since).order_by(Alert.timestamp.asc())
    )
    alerts = result.scalars().all()

    # Bucket into hourly bins
    buckets: dict[str, int] = {}
    for h in range(hours):
        ts = since + timedelta(hours=h)
        key = ts.strftime("%Y-%m-%dT%H:00:00")
        buckets[key] = 0

    for alert in alerts:
        key = alert.timestamp.strftime("%Y-%m-%dT%H:00:00")
        if key in buckets:
            buckets[key] += 1

    return [{"timestamp": k, "count": v} for k, v in buckets.items()]


@router.get("/severity-distribution")
async def get_severity_distribution(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get alert counts grouped by severity."""
    result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
    )
    rows = result.all()
    return [{"severity": row[0], "count": row[1]} for row in rows]


@router.get("/module-activity")
async def get_module_activity(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get event counts by module source."""
    result = await db.execute(
        select(Alert.module_source, func.count(Alert.id))
        .group_by(Alert.module_source)
        .order_by(func.count(Alert.id).desc())
    )
    rows = result.all()
    return [{"module": row[0], "count": row[1]} for row in rows]


@router.get("/threat-history")
async def get_threat_history(
    hours: int = Query(24, ge=1, le=168),
    current_user: dict = Depends(get_current_user),
):
    """Get threat level samples over time (from in-memory threat intelligence)."""
    from ...dependencies import get_threat_intelligence
    try:
        ti = get_threat_intelligence()
        feed = ti.get_threat_feed(limit=200)
        return feed[:100]  # Return recent threat events
    except Exception:
        return []
