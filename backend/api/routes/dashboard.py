"""Dashboard routes — system overview and stats."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD
from ...config import get_config
from ...dependencies import (
    get_db,
    get_vpn_guardian,
    get_network_sentinel,
    get_brute_force_shield,
    get_file_integrity,
    get_process_analyzer,
    get_vuln_scanner,
    get_email_analyzer,
    get_resource_monitor,
    get_persistence_scanner,
    get_threat_intelligence,
)
from ...models.alert import Alert
from ...models.event import Event

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _get_live_module_statuses() -> list[dict]:
    """Build module status list from live singletons."""
    config = get_config()
    modules = []

    # VPN Guardian is always enabled
    try:
        vpn = get_vpn_guardian()
        modules.append({"name": "vpn_guardian", "enabled": True, "health": vpn.health_status})
    except Exception:
        modules.append({"name": "vpn_guardian", "enabled": True, "health": "unknown"})

    module_map = [
        ("network_sentinel", config.module_network_sentinel, get_network_sentinel),
        ("brute_force_shield", config.module_brute_force_shield, get_brute_force_shield),
        ("file_integrity", config.module_file_integrity, get_file_integrity),
        ("process_analyzer", config.module_process_analyzer, get_process_analyzer),
        ("vuln_scanner", config.module_vuln_scanner, get_vuln_scanner),
        ("email_analyzer", config.module_email_analyzer, get_email_analyzer),
        ("resource_monitor", config.module_resource_monitor, get_resource_monitor),
        ("persistence_scanner", config.module_persistence_scanner, get_persistence_scanner),
        ("threat_intelligence", config.module_threat_intelligence, get_threat_intelligence),
    ]

    for name, enabled, getter in module_map:
        if enabled:
            try:
                mod = getter()
                modules.append({"name": name, "enabled": True, "health": mod.health_status})
            except Exception:
                modules.append({"name": name, "enabled": True, "health": "unknown"})
        else:
            modules.append({"name": name, "enabled": False, "health": "disabled"})

    return modules


@router.get("/summary")
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
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

    # Module statuses from live singletons
    modules = _get_live_module_statuses()

    # VPN status
    vpn_guardian = get_vpn_guardian()
    vpn_status = vpn_guardian.detector.state.to_dict()

    return {
        "alerts": alert_counts,
        "events_today": events_today,
        "modules": modules,
        "vpn": vpn_status,
    }
