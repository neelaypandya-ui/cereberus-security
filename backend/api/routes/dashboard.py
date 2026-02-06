"""Dashboard routes — system overview and stats."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...dependencies import get_current_user, get_db, get_vpn_guardian
from ...models.alert import Alert
from ...models.event import Event
from ...models.settings import ModuleStatus

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get dashboard summary with key metrics."""
    # Count alerts by severity
    alert_counts = {}
    for severity in ["critical", "high", "medium", "low", "info"]:
        result = await db.execute(
            select(func.count(Alert.id)).where(
                Alert.severity == severity,
                Alert.acknowledged == False,
            )
        )
        alert_counts[severity] = result.scalar() or 0

    # Total events today
    from datetime import datetime, timezone
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    result = await db.execute(
        select(func.count(Event.id)).where(Event.timestamp >= today_start)
    )
    events_today = result.scalar() or 0

    # Module statuses
    result = await db.execute(select(ModuleStatus))
    modules = [
        {
            "name": m.module_name,
            "enabled": m.enabled,
            "health": m.health_status,
        }
        for m in result.scalars().all()
    ]

    # VPN status
    vpn_guardian = get_vpn_guardian()
    vpn_status = vpn_guardian.detector.state.to_dict()

    return {
        "alerts": alert_counts,
        "events_today": events_today,
        "modules": modules,
        "vpn": vpn_status,
    }
