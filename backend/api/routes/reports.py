"""Report generation routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_EXPORT_DATA
from ...dependencies import (
    get_db,
    get_resource_monitor,
    get_threat_intelligence,
    get_vuln_scanner,
)
from ...models.alert import Alert
from ...utils.report_template import render_report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate")
async def generate_report(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_EXPORT_DATA)),
):
    """Generate a comprehensive security assessment HTML report."""
    # Collect alerts
    result = await db.execute(
        select(Alert).order_by(Alert.timestamp.desc()).limit(200)
    )
    alert_rows = result.scalars().all()
    alerts = [
        {
            "severity": a.severity,
            "title": a.title,
            "description": a.description,
            "module_source": a.module_source,
            "timestamp": a.timestamp.isoformat() if a.timestamp else "",
        }
        for a in alert_rows
    ]

    # Collect threat level
    threat_level = "none"
    try:
        ti = get_threat_intelligence()
        threat_level = ti.get_threat_level()
    except Exception:
        pass

    # Collect vulnerabilities
    vulnerabilities = []
    try:
        vs = get_vuln_scanner()
        vulnerabilities = vs.get_vulnerabilities()
    except Exception:
        pass

    # Collect module status (from dashboard summary pattern)
    modules = []
    try:
        from ...dependencies import (
            get_vpn_guardian, get_network_sentinel, get_brute_force_shield,
            get_file_integrity, get_process_analyzer, get_email_analyzer,
            get_persistence_scanner,
        )
        from ...config import get_config
        config = get_config()
        module_checks = [
            ("vpn_guardian", get_vpn_guardian, True),
            ("network_sentinel", get_network_sentinel, config.module_network_sentinel),
            ("brute_force_shield", get_brute_force_shield, config.module_brute_force_shield),
            ("file_integrity", get_file_integrity, config.module_file_integrity),
            ("process_analyzer", get_process_analyzer, config.module_process_analyzer),
            ("vuln_scanner", get_vuln_scanner, config.module_vuln_scanner),
            ("email_analyzer", get_email_analyzer, config.module_email_analyzer),
            ("resource_monitor", get_resource_monitor, config.module_resource_monitor),
            ("persistence_scanner", get_persistence_scanner, config.module_persistence_scanner),
            ("threat_intelligence", get_threat_intelligence, config.module_threat_intelligence),
        ]
        for name, getter, enabled in module_checks:
            try:
                m = getter()
                health = await m.health_check()
                modules.append({"name": name, "enabled": enabled, "health": health.get("status", "unknown")})
            except Exception:
                modules.append({"name": name, "enabled": enabled, "health": "error"})
    except Exception:
        pass

    # Collect resources
    resources = {}
    try:
        rm = get_resource_monitor()
        resources = rm.get_current()
    except Exception:
        pass

    # Generate recommendations
    recommendations = []
    critical_count = sum(1 for a in alerts if a["severity"] == "critical")
    if critical_count > 0:
        recommendations.append(f"Investigate and resolve {critical_count} critical alert(s) immediately.")
    if any(v.get("severity") == "critical" for v in vulnerabilities):
        recommendations.append("Patch critical vulnerabilities as soon as possible.")
    if threat_level in ("high", "critical"):
        recommendations.append("Threat level is elevated — review threat correlations and consider incident response.")
    if resources.get("cpu_percent", 0) > 90:
        recommendations.append("CPU usage is critically high — investigate resource-intensive processes.")
    if resources.get("memory_percent", 0) > 85:
        recommendations.append("Memory usage is high — consider freeing resources or increasing capacity.")
    if not recommendations:
        recommendations.append("System appears to be in a healthy state. Continue monitoring.")

    # Render
    html = render_report({
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "threat_level": threat_level,
        "alerts": alerts,
        "vulnerabilities": vulnerabilities,
        "modules": modules,
        "resources": resources,
        "recommendations": recommendations,
    })

    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=cereberus-report.html"},
    )
