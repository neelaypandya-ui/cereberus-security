"""Report generation routes."""

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_EXPORT_DATA
from ...config import get_config
from ...dependencies import (
    get_db,
    get_resource_monitor,
    get_threat_intelligence,
    get_vuln_scanner,
    get_vpn_guardian,
    get_network_sentinel,
    get_brute_force_shield,
    get_file_integrity,
    get_process_analyzer,
    get_persistence_scanner,
    get_event_log_monitor,
    get_ransomware_detector,
    get_commander_bond,
    get_memory_scanner,
    get_disk_analyzer,
    get_anomaly_detector,
    get_ensemble_detector,
    get_behavioral_baseline,
    get_rule_engine,
    get_yara_scanner,
    get_incident_manager,
)
from ...models.alert import Alert
from ...utils.report_template import render_report

from .checklists import (
    verify_situation_room,
    verify_shield,
    verify_sword,
    verify_threat_assessment,
    verify_ai_warfare,
    verify_incident_response,
    verify_combat_readiness,
)

router = APIRouter(prefix="/reports", tags=["reports"])


def _safe_get(getter):
    """Call a dependency getter, returning None if not initialised."""
    try:
        return getter()
    except Exception:
        return None


@router.post("/generate")
async def generate_report(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_EXPORT_DATA)),
):
    """Generate a comprehensive security assessment HTML report."""
    config = get_config()

    # --- Alerts ---
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

    # --- Threat level ---
    threat_level = "none"
    try:
        ti = get_threat_intelligence()
        threat_level = ti.get_threat_level()
    except Exception:
        pass

    # --- Vulnerabilities ---
    vulnerabilities = []
    try:
        vs = get_vuln_scanner()
        vulnerabilities = vs.get_vulnerabilities()
    except Exception:
        pass

    # --- Module health (all 16) — parallelised for speed ---
    module_checks = [
        ("vpn_guardian", get_vpn_guardian, True),
        ("network_sentinel", get_network_sentinel, config.module_network_sentinel),
        ("brute_force_shield", get_brute_force_shield, config.module_brute_force_shield),
        ("file_integrity", get_file_integrity, config.module_file_integrity),
        ("process_analyzer", get_process_analyzer, config.module_process_analyzer),
        ("vuln_scanner", get_vuln_scanner, config.module_vuln_scanner),
        ("resource_monitor", get_resource_monitor, config.module_resource_monitor),
        ("persistence_scanner", get_persistence_scanner, config.module_persistence_scanner),
        ("threat_intelligence", get_threat_intelligence, config.module_threat_intelligence),
        ("event_log_monitor", get_event_log_monitor, config.module_event_log_monitor),
        ("ransomware_detector", get_ransomware_detector, config.module_ransomware_detector),
        ("commander_bond", get_commander_bond, config.module_commander_bond),
        ("memory_scanner", get_memory_scanner, config.module_memory_scanner),
        ("disk_analyzer", get_disk_analyzer, True),
    ]

    async def _check_module(name, getter, enabled):
        try:
            m = getter()
            if hasattr(m, "health_check"):
                health = await asyncio.wait_for(m.health_check(), timeout=5.0)
                return {"name": name, "enabled": enabled, "health": health.get("status", "unknown")}
            return {"name": name, "enabled": enabled, "health": "available"}
        except Exception:
            return {"name": name, "enabled": enabled, "health": "error"}

    modules = list(await asyncio.gather(
        *(_check_module(n, g, e) for n, g, e in module_checks)
    ))

    # --- Resources ---
    resources = {}
    try:
        rm = get_resource_monitor()
        resources = rm.get_current()
    except Exception:
        pass

    # --- Run checklist + incident stats in parallel (both need await) ---
    async def _get_checklists():
        try:
            cats = await asyncio.gather(
                verify_situation_room(db),
                verify_shield(db),
                verify_sword(db),
                verify_threat_assessment(db),
                verify_ai_warfare(db),
                verify_incident_response(db),
                verify_combat_readiness(db),
            )
            return list(cats)
        except Exception:
            return []

    async def _get_incidents():
        try:
            im = _safe_get(get_incident_manager)
            if im:
                return await im.get_stats()
        except Exception:
            pass
        return {
            "total": 0,
            "by_status": {"open": 0, "investigating": 0, "contained": 0, "resolved": 0, "closed": 0},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }

    checklist_categories, incident_stats = await asyncio.gather(
        _get_checklists(), _get_incidents()
    )

    checklist_total_passed = sum(c["passed_count"] for c in checklist_categories)
    checklist_total_items = sum(c["total_count"] for c in checklist_categories)
    checklist_completion = round(
        (checklist_total_passed / checklist_total_items * 100), 1
    ) if checklist_total_items > 0 else 0.0

    # --- AI warfare, detection, bond status (all sync — fast) ---
    ai_status = {
        "ensemble_initialized": False, "drift_score": 0.0,
        "baseline_coverage": 0, "baseline_samples": 0,
    }
    try:
        ad = _safe_get(get_anomaly_detector)
        if ad:
            ai_status["ensemble_initialized"] = getattr(ad, "initialized", False)
            drift = getattr(ad, "drift_score", 0.0)
            if hasattr(ad, "get_drift_score"):
                drift = ad.get_drift_score()
            ai_status["drift_score"] = drift
    except Exception:
        pass
    try:
        bb = _safe_get(get_behavioral_baseline)
        if bb and hasattr(bb, "get_learning_progress"):
            progress = bb.get_learning_progress()
            if isinstance(progress, dict):
                ai_status["baseline_coverage"] = progress.get("coverage_percent", 0)
                ai_status["baseline_samples"] = progress.get("total_samples", 0)
    except Exception:
        pass

    detection_status = {
        "rule_engine": {"rules_enabled": 0, "rules_total": 0, "total_matches": 0, "by_severity": {}, "by_category": {}},
        "yara": {"rules_loaded": 0, "compiled": False, "total_scans": 0, "total_matches": 0, "files_scanned": 0, "yara_available": False},
    }
    try:
        re = _safe_get(get_rule_engine)
        if re:
            detection_status["rule_engine"] = re.get_stats()
    except Exception:
        pass
    try:
        ys = _safe_get(get_yara_scanner)
        if ys:
            detection_status["yara"] = ys.get_stats()
    except Exception:
        pass

    bond_status = {
        "sword": {"enabled": False, "lockout": False, "policies_loaded": 0},
        "overwatch": {"status": "offline", "tamper_count": 0, "files_baselined": 0},
        "guardian": {"containment_level": -1, "level_name": "unknown", "lockdown_active": False},
    }
    try:
        bond = _safe_get(get_commander_bond)
        if bond:
            if hasattr(bond, "get_sword_stats"):
                ss = bond.get_sword_stats()
                if isinstance(ss, dict):
                    bond_status["sword"] = {
                        "enabled": ss.get("enabled", False),
                        "lockout": ss.get("lockout", False),
                        "policies_loaded": ss.get("policies_loaded", 0),
                    }
            if hasattr(bond, "get_overwatch_status"):
                ow = bond.get_overwatch_status()
                if isinstance(ow, dict):
                    bond_status["overwatch"] = {
                        "status": ow.get("status", "offline"),
                        "tamper_count": ow.get("tamper_count", 0),
                        "files_baselined": ow.get("files_baselined", 0),
                    }
            if hasattr(bond, "get_guardian_status"):
                gs = bond.get_guardian_status()
                if isinstance(gs, dict):
                    bond_status["guardian"] = {
                        "containment_level": gs.get("containment_level", -1),
                        "level_name": gs.get("level_name", "unknown"),
                        "lockdown_active": gs.get("lockdown_active", False),
                    }
    except Exception:
        pass

    # --- Recommendations (enhanced) ---
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

    # AI-specific recommendations
    if ai_status["drift_score"] >= 0.5:
        recommendations.append(f"AI model drift is elevated ({ai_status['drift_score']:.3f}) — consider retraining the anomaly detector.")
    if not ai_status["ensemble_initialized"]:
        recommendations.append("AI ensemble detector is not initialized — anomaly detection may be degraded.")
    # Detection engine recommendations
    re_stats = detection_status["rule_engine"]
    if re_stats.get("rules_enabled", 0) < 50:
        recommendations.append(f"Only {re_stats.get('rules_enabled', 0)}/50 detection rules enabled — review rule configuration.")
    yara_stats = detection_status["yara"]
    if not yara_stats.get("compiled", False):
        recommendations.append("YARA rules are not compiled — Q-Branch scanning is non-operational.")

    # Bond recommendations
    if bond_status["sword"].get("lockout"):
        recommendations.append("Sword Protocol is in LOCKOUT — review and resolve the lockout condition.")
    if bond_status["overwatch"].get("tamper_count", 0) > 0:
        recommendations.append(f"Overwatch detected {bond_status['overwatch']['tamper_count']} tampering event(s) — investigate immediately.")

    # Incident recommendations
    open_incidents = incident_stats.get("by_status", {}).get("open", 0)
    if open_incidents > 0:
        recommendations.append(f"{open_incidents} open incident(s) require investigation.")

    # Checklist recommendations
    if checklist_total_items > 0 and checklist_completion < 80:
        recommendations.append(f"System verification score is {checklist_completion}% — address failing checks to improve readiness.")

    if not recommendations:
        recommendations.append("System appears to be in a healthy state. Continue monitoring.")

    # --- Render ---
    html = render_report({
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "threat_level": threat_level,
        "alerts": alerts,
        "vulnerabilities": vulnerabilities,
        "modules": modules,
        "resources": resources,
        "recommendations": recommendations,
        "checklist_categories": checklist_categories,
        "checklist_completion": checklist_completion,
        "checklist_total_passed": checklist_total_passed,
        "checklist_total_items": checklist_total_items,
        "ai_status": ai_status,
        "detection_status": detection_status,
        "bond_status": bond_status,
        "incident_stats": incident_stats,
    })

    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=cereberus-report.html"},
    )
