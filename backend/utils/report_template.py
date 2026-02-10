"""HTML report template for security assessment reports."""

from datetime import datetime, timezone


def _html_escape(text: str) -> str:
    """Minimal HTML escape for user-facing strings."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _sev_color(sev: str) -> str:
    return {
        "critical": "#ff1744", "high": "#ff5722", "medium": "#ff9800",
        "low": "#ffc107", "info": "#2196f3",
    }.get(sev, "#666")


def _section_heading(title: str) -> str:
    return f'<h2 style="color:#00e5ff;font-size:16px;margin-top:32px;margin-bottom:12px;letter-spacing:2px;">{title}</h2>'


def _card_box(inner: str) -> str:
    return f'<div style="background:#161616;padding:20px;border-radius:8px;border:1px solid #2d2d2d;margin-bottom:24px;">{inner}</div>'


def _stat_card(label: str, value: str, color: str = "#e8e8e8") -> str:
    return (
        '<div style="background:#1a1a1a;padding:16px 24px;border-radius:8px;border:1px solid #2d2d2d;min-width:140px;">'
        f'<div style="color:#666;font-size:10px;letter-spacing:1px;margin-bottom:4px;">{label}</div>'
        f'<div style="font-size:22px;font-weight:700;color:{color};">{value}</div>'
        '</div>'
    )


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_executive_summary(data: dict) -> str:
    threat_level = data.get("threat_level", "none")
    alerts = data.get("alerts", [])
    vulnerabilities = data.get("vulnerabilities", [])
    checklist_completion = data.get("checklist_completion", 0.0)
    checklist_total_passed = data.get("checklist_total_passed", 0)
    checklist_total_items = data.get("checklist_total_items", 0)

    severity_counts: dict[str, int] = {}
    for a in alerts:
        sev = a.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    threat_color = {
        "none": "#4caf50", "low": "#2196f3", "medium": "#ff9800",
        "high": "#ff5722", "critical": "#ff1744",
    }.get(threat_level, "#666")

    verify_color = "#4caf50" if checklist_completion >= 80 else "#ff9800" if checklist_completion >= 50 else "#ff1744"

    return f"""
    {_section_heading("EXECUTIVE SUMMARY")}
    <div style="background:#161616;padding:20px;border-radius:8px;border:1px solid #2d2d2d;margin-bottom:24px;">
        <div style="display:flex;align-items:center;gap:16px;">
            <div style="font-size:12px;color:#a0a0a0;">Overall Threat Level:</div>
            <div style="font-size:20px;font-weight:700;color:{threat_color};text-transform:uppercase;letter-spacing:2px;">{threat_level}</div>
        </div>
        <div style="display:flex;gap:24px;margin-top:16px;flex-wrap:wrap;">
            <div><span style="color:#666;">Total Alerts:</span> <strong>{len(alerts)}</strong></div>
            <div><span style="color:#666;">Critical:</span> <strong style="color:#ff1744;">{severity_counts.get('critical',0)}</strong></div>
            <div><span style="color:#666;">High:</span> <strong style="color:#ff5722;">{severity_counts.get('high',0)}</strong></div>
            <div><span style="color:#666;">Medium:</span> <strong style="color:#ff9800;">{severity_counts.get('medium',0)}</strong></div>
            <div><span style="color:#666;">Vulnerabilities:</span> <strong>{len(vulnerabilities)}</strong></div>
        </div>
        <div style="display:flex;align-items:center;gap:16px;margin-top:16px;padding-top:16px;border-top:1px solid #2d2d2d;">
            <div style="font-size:12px;color:#a0a0a0;">System Verification:</div>
            <div style="font-size:20px;font-weight:700;color:{verify_color};">{checklist_completion}%</div>
            <div style="font-size:12px;color:#666;">({checklist_total_passed}/{checklist_total_items} checks passed)</div>
        </div>
    </div>"""


def _build_checklist_scorecard(data: dict) -> str:
    categories = data.get("checklist_categories", [])
    if not categories:
        return ""

    completion = data.get("checklist_completion", 0.0)
    total_passed = data.get("checklist_total_passed", 0)
    total_items = data.get("checklist_total_items", 0)

    score_color = "#4caf50" if completion >= 80 else "#ff9800" if completion >= 50 else "#ff1744"

    # Large centered score
    html = f"""
    {_section_heading("SYSTEM VERIFICATION SCORECARD")}
    <div style="background:#161616;padding:24px;border-radius:8px;border:1px solid #2d2d2d;margin-bottom:24px;">
        <div style="text-align:center;margin-bottom:24px;">
            <div style="font-size:56px;font-weight:700;color:{score_color};">{completion}%</div>
            <div style="color:#666;font-size:12px;letter-spacing:1px;">{total_passed} / {total_items} CHECKS PASSED</div>
        </div>"""

    for cat in categories:
        cat_passed = cat.get("passed_count", 0)
        cat_total = cat.get("total_count", 0)
        cat_pct = round(cat_passed / cat_total * 100) if cat_total > 0 else 0
        bar_color = "#4caf50" if cat_pct >= 80 else "#ff9800" if cat_pct >= 50 else "#ff1744"

        html += f"""
        <div style="margin-bottom:20px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                <div style="font-size:12px;font-weight:700;color:#e8e8e8;letter-spacing:1px;">
                    {cat.get("icon", "")} {_html_escape(cat.get("label", ""))}
                </div>
                <div style="font-size:12px;color:#a0a0a0;">{cat_passed}/{cat_total}</div>
            </div>
            <div style="background:#0a0a0a;border-radius:4px;height:8px;overflow:hidden;">
                <div style="background:{bar_color};height:100%;width:{cat_pct}%;border-radius:4px;"></div>
            </div>
            <table style="margin-top:8px;font-size:12px;">"""

        for item in cat.get("items", []):
            passed = item.get("passed", False)
            icon = "&#10003;" if passed else "&#10007;"
            icon_color = "#4caf50" if passed else "#ff1744"
            html += f"""
                <tr>
                    <td style="padding:3px 10px 3px 0;color:{icon_color};font-weight:700;width:20px;">{icon}</td>
                    <td style="padding:3px 10px 3px 0;color:#e8e8e8;">{_html_escape(item.get("label", ""))}</td>
                    <td style="padding:3px 0;color:#666;">{_html_escape(item.get("detail", ""))}</td>
                </tr>"""

        html += """
            </table>
        </div>"""

    html += "</div>"
    return html


def _build_alert_summary(data: dict) -> str:
    alerts = data.get("alerts", [])

    rows = ""
    for a in alerts[:50]:
        sev = a.get("severity", "info")
        rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">
                <span style="color:{_sev_color(sev)};font-weight:700;text-transform:uppercase;">{sev}</span>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">{_html_escape(a.get('title',''))}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;color:#666;">{_html_escape(a.get('module_source',''))}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;color:#666;">{_html_escape(a.get('timestamp',''))}</td>
        </tr>"""

    empty = '<tr><td colspan="4" style="padding:20px;text-align:center;color:#666;">No alerts</td></tr>'

    return f"""
    {_section_heading("ALERT SUMMARY")}
    <div style="background:#161616;border-radius:8px;border:1px solid #2d2d2d;overflow:auto;">
        <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Source</th><th>Time</th></tr></thead>
            <tbody>{rows if rows else empty}</tbody>
        </table>
    </div>"""


def _build_vuln_findings(data: dict) -> str:
    vulnerabilities = data.get("vulnerabilities", [])

    rows = ""
    for v in vulnerabilities[:30]:
        sev = v.get("severity", "info")
        rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">
                <span style="color:{_sev_color(sev)};font-weight:700;text-transform:uppercase;">{sev}</span>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">{_html_escape(v.get('title',''))}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;color:#a0a0a0;">{_html_escape(v.get('description','')[:120])}</td>
        </tr>"""

    empty = '<tr><td colspan="3" style="padding:20px;text-align:center;color:#666;">No vulnerabilities found</td></tr>'

    return f"""
    {_section_heading("VULNERABILITY FINDINGS")}
    <div style="background:#161616;border-radius:8px;border:1px solid #2d2d2d;overflow:auto;">
        <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Description</th></tr></thead>
            <tbody>{rows if rows else empty}</tbody>
        </table>
    </div>"""


def _build_module_health(data: dict) -> str:
    modules = data.get("modules", [])

    rows = ""
    for m in modules:
        health = m.get("health", "unknown")
        status_color = "#4caf50" if health in ("running", "available") else "#f44336"
        rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">{_html_escape(m.get('name',''))}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">
                <span style="color:{status_color};">{'Enabled' if m.get('enabled') else 'Disabled'}</span>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;color:{status_color};">{health}</td>
        </tr>"""

    empty = '<tr><td colspan="3" style="padding:20px;text-align:center;color:#666;">No modules</td></tr>'

    return f"""
    {_section_heading("MODULE HEALTH")}
    <div style="background:#161616;border-radius:8px;border:1px solid #2d2d2d;overflow:auto;">
        <table>
            <thead><tr><th>Module</th><th>Status</th><th>Health</th></tr></thead>
            <tbody>{rows if rows else empty}</tbody>
        </table>
    </div>"""


def _build_ai_warfare(data: dict) -> str:
    ai = data.get("ai_status", {})
    if not ai:
        return ""

    ensemble_init = ai.get("ensemble_initialized", False)
    drift = ai.get("drift_score", 0.0)
    lstm_ok = ai.get("lstm_initialized", False) or ai.get("lstm_has_model", False)
    baseline_cov = ai.get("baseline_coverage", 0)
    baseline_samples = ai.get("baseline_samples", 0)

    ensemble_text = "ONLINE" if ensemble_init else "OFFLINE"
    ensemble_color = "#4caf50" if ensemble_init else "#ff1744"

    drift_color = "#4caf50" if drift < 0.3 else "#ff9800" if drift < 0.5 else "#ff1744"

    lstm_text = "OPERATIONAL" if lstm_ok else "NO MODEL"
    lstm_color = "#4caf50" if lstm_ok else "#ff9800"

    baseline_color = "#4caf50" if baseline_cov > 50 else "#ff9800" if baseline_cov > 0 else "#666"

    return f"""
    {_section_heading("AI WARFARE STATUS")}
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px;">
        {_stat_card("ENSEMBLE DETECTOR", ensemble_text, ensemble_color)}
        {_stat_card("MODEL DRIFT", f"{drift:.3f}", drift_color)}
        {_stat_card("LSTM FORECASTER", lstm_text, lstm_color)}
        {_stat_card("BASELINE COVERAGE", f"{baseline_cov}%", baseline_color)}
    </div>
    <div style="background:#161616;padding:12px 20px;border-radius:8px;border:1px solid #2d2d2d;margin-bottom:24px;">
        <span style="color:#666;font-size:12px;">Behavioral baseline samples collected: </span>
        <strong style="color:#e8e8e8;">{baseline_samples:,}</strong>
    </div>"""


def _build_detection_engine(data: dict) -> str:
    det = data.get("detection_status", {})
    if not det:
        return ""

    re = det.get("rule_engine", {})
    yara = det.get("yara", {})

    re_enabled = re.get("rules_enabled", 0)
    re_total = re.get("rules_total", 0)
    re_matches = re.get("total_matches", 0)
    re_by_sev = re.get("by_severity", {})

    yara_loaded = yara.get("rules_loaded", 0)
    yara_compiled = yara.get("compiled", False)
    yara_scans = yara.get("total_scans", 0)
    yara_matches = yara.get("total_matches", 0)
    yara_files = yara.get("files_scanned", 0)
    yara_available = yara.get("yara_available", False)

    compiled_text = "COMPILED" if yara_compiled else "NOT COMPILED"
    compiled_color = "#4caf50" if yara_compiled else "#ff1744"
    yara_avail_text = "AVAILABLE" if yara_available else "UNAVAILABLE"
    yara_avail_color = "#4caf50" if yara_available else "#ff1744"

    sev_html = ""
    for sev_name in ("critical", "high", "medium", "low"):
        count = re_by_sev.get(sev_name, 0)
        if count > 0:
            sev_html += f'<span style="color:{_sev_color(sev_name)};margin-right:12px;">{sev_name}: {count}</span>'

    return f"""
    {_section_heading("DETECTION ENGINE")}
    <div style="display:flex;gap:24px;flex-wrap:wrap;margin-bottom:24px;">
        <div style="flex:1;min-width:300px;background:#161616;padding:20px;border-radius:8px;border:1px solid #2d2d2d;">
            <div style="color:#00e5ff;font-size:12px;letter-spacing:1px;margin-bottom:16px;font-weight:700;">RULE ENGINE</div>
            <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;">
                {_stat_card("RULES", f"{re_enabled}/{re_total}", "#e8e8e8")}
                {_stat_card("MATCHES", f"{re_matches:,}", "#e8e8e8")}
            </div>
            <div style="font-size:12px;margin-top:8px;">
                {sev_html if sev_html else '<span style="color:#666;">No matches by severity</span>'}
            </div>
        </div>
        <div style="flex:1;min-width:300px;background:#161616;padding:20px;border-radius:8px;border:1px solid #2d2d2d;">
            <div style="color:#00e5ff;font-size:12px;letter-spacing:1px;margin-bottom:16px;font-weight:700;">Q-BRANCH YARA</div>
            <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;">
                {_stat_card("RULES LOADED", str(yara_loaded), "#e8e8e8")}
                {_stat_card("STATUS", compiled_text, compiled_color)}
            </div>
            <div style="font-size:12px;color:#a0a0a0;margin-top:8px;">
                <span style="margin-right:16px;">YARA Engine: <strong style="color:{yara_avail_color};">{yara_avail_text}</strong></span>
                <span style="margin-right:16px;">Scans: <strong style="color:#e8e8e8;">{yara_scans:,}</strong></span>
                <span style="margin-right:16px;">Files: <strong style="color:#e8e8e8;">{yara_files:,}</strong></span>
                <span>Matches: <strong style="color:#e8e8e8;">{yara_matches:,}</strong></span>
            </div>
        </div>
    </div>"""


def _build_bond_operations(data: dict) -> str:
    bond = data.get("bond_status", {})
    if not bond:
        return ""

    sword = bond.get("sword", {})
    overwatch = bond.get("overwatch", {})
    guardian = bond.get("guardian", {})

    # Sword Protocol
    sword_enabled = sword.get("enabled", False)
    sword_lockout = sword.get("lockout", False)
    sword_policies = sword.get("policies_loaded", 0)
    if sword_lockout:
        sword_text = "LOCKOUT"
        sword_color = "#ff1744"
    elif sword_enabled:
        sword_text = "ARMED"
        sword_color = "#4caf50"
    else:
        sword_text = "DISABLED"
        sword_color = "#666"

    # Overwatch
    ow_status = overwatch.get("status", "offline")
    ow_tamper = overwatch.get("tamper_count", 0)
    ow_files = overwatch.get("files_baselined", 0)
    ow_color = "#4caf50" if ow_status in ("monitoring", "active") else "#ff9800" if ow_status != "offline" else "#666"
    tamper_color = "#4caf50" if ow_tamper == 0 else "#ff1744"

    # Guardian
    g_level = guardian.get("containment_level", -1)
    g_name = guardian.get("level_name", "unknown")
    g_lockdown = guardian.get("lockdown_active", False)
    g_color = "#4caf50" if g_level == 0 else "#ff9800" if g_level <= 2 else "#ff1744"

    return f"""
    {_section_heading("BOND OPERATIONS")}
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px;">
        <div style="flex:1;min-width:200px;background:#161616;padding:20px;border-radius:8px;border:1px solid #2d2d2d;">
            <div style="color:#00e5ff;font-size:10px;letter-spacing:1px;margin-bottom:8px;">SWORD PROTOCOL</div>
            <div style="font-size:24px;font-weight:700;color:{sword_color};">{sword_text}</div>
            <div style="color:#666;font-size:12px;margin-top:8px;">{sword_policies} policies loaded</div>
        </div>
        <div style="flex:1;min-width:200px;background:#161616;padding:20px;border-radius:8px;border:1px solid #2d2d2d;">
            <div style="color:#00e5ff;font-size:10px;letter-spacing:1px;margin-bottom:8px;">OVERWATCH</div>
            <div style="font-size:24px;font-weight:700;color:{ow_color};text-transform:uppercase;">{_html_escape(ow_status)}</div>
            <div style="color:#666;font-size:12px;margin-top:8px;">
                {ow_files} files baselined &middot;
                <span style="color:{tamper_color};">{ow_tamper} tamper(s)</span>
            </div>
        </div>
        <div style="flex:1;min-width:200px;background:#161616;padding:20px;border-radius:8px;border:1px solid #2d2d2d;">
            <div style="color:#00e5ff;font-size:10px;letter-spacing:1px;margin-bottom:8px;">GUARDIAN PROTOCOL</div>
            <div style="font-size:24px;font-weight:700;color:{g_color};">LEVEL {g_level}</div>
            <div style="color:#666;font-size:12px;margin-top:8px;">
                {_html_escape(g_name)}{' — LOCKDOWN ACTIVE' if g_lockdown else ''}
            </div>
        </div>
    </div>"""


def _build_incident_response(data: dict) -> str:
    stats = data.get("incident_stats", {})
    total = stats.get("total", 0)
    by_status = stats.get("by_status", {})
    by_severity = stats.get("by_severity", {})

    status_items = ""
    status_colors = {
        "open": "#ff1744", "investigating": "#ff9800", "contained": "#ffc107",
        "resolved": "#4caf50", "closed": "#666",
    }
    for s_name in ("open", "investigating", "contained", "resolved", "closed"):
        count = by_status.get(s_name, 0)
        color = status_colors.get(s_name, "#666")
        status_items += f'<div style="margin-right:24px;"><span style="color:#666;font-size:12px;">{s_name.upper()}:</span> <strong style="color:{color};font-size:18px;">{count}</strong></div>'

    severity_items = ""
    for sev_name in ("critical", "high", "medium", "low"):
        count = by_severity.get(sev_name, 0)
        severity_items += f'<div style="margin-right:24px;"><span style="color:#666;font-size:12px;">{sev_name.upper()}:</span> <strong style="color:{_sev_color(sev_name)};font-size:18px;">{count}</strong></div>'

    return f"""
    {_section_heading("INCIDENT RESPONSE")}
    <div style="background:#161616;padding:20px;border-radius:8px;border:1px solid #2d2d2d;margin-bottom:24px;">
        <div style="text-align:center;margin-bottom:16px;">
            <div style="color:#666;font-size:10px;letter-spacing:1px;">TOTAL INCIDENTS</div>
            <div style="font-size:36px;font-weight:700;color:#e8e8e8;">{total}</div>
        </div>
        <div style="padding-top:16px;border-top:1px solid #2d2d2d;">
            <div style="color:#00e5ff;font-size:10px;letter-spacing:1px;margin-bottom:12px;">BY STATUS</div>
            <div style="display:flex;flex-wrap:wrap;">{status_items}</div>
        </div>
        <div style="padding-top:16px;margin-top:16px;border-top:1px solid #2d2d2d;">
            <div style="color:#00e5ff;font-size:10px;letter-spacing:1px;margin-bottom:12px;">BY SEVERITY</div>
            <div style="display:flex;flex-wrap:wrap;">{severity_items}</div>
        </div>
    </div>"""


def _build_resources(data: dict) -> str:
    resources = data.get("resources", {})
    if not resources:
        return ""

    return f"""
    {_section_heading("SYSTEM RESOURCES")}
    <div style="display:flex;gap:24px;flex-wrap:wrap;margin-bottom:24px;">
        {_stat_card("CPU", f"{resources.get('cpu_percent', 'N/A')}%")}
        {_stat_card("MEMORY", f"{resources.get('memory_percent', 'N/A')}%")}
        {_stat_card("DISK", f"{resources.get('disk_percent', 'N/A')}%")}
    </div>"""


def _build_recommendations(data: dict) -> str:
    recommendations = data.get("recommendations", [])

    items = ""
    for r in recommendations:
        items += f'<li style="margin-bottom:8px;color:#a0a0a0;">{_html_escape(r)}</li>'

    empty = '<li style="color:#666;">No specific recommendations at this time.</li>'

    return f"""
    {_section_heading("RECOMMENDATIONS")}
    <div style="background:#161616;padding:20px;border-radius:8px;border:1px solid #2d2d2d;">
        <ul style="padding-left:20px;">{items if items else empty}</ul>
    </div>"""


# ---------------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------------

def render_report(data: dict) -> str:
    """Render a security assessment report as HTML.

    Args:
        data: Dict with keys: threat_level, alerts, vulnerabilities, modules,
              resources, recommendations, generated_at, checklist_categories,
              checklist_completion, checklist_total_passed, checklist_total_items,
              ai_status, detection_status, bond_status, incident_stats.

    Returns:
        Complete HTML string.
    """
    generated_at = data.get("generated_at", datetime.now(timezone.utc).isoformat())

    body = (
        _build_executive_summary(data)
        + _build_checklist_scorecard(data)
        + _build_alert_summary(data)
        + _build_vuln_findings(data)
        + _build_module_health(data)
        + _build_ai_warfare(data)
        + _build_detection_engine(data)
        + _build_bond_operations(data)
        + _build_incident_response(data)
        + _build_resources(data)
        + _build_recommendations(data)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CEREBERUS Security Assessment Report</title>
<style>
    body {{
        font-family: 'Segoe UI', system-ui, sans-serif;
        background: #0a0a0a;
        color: #e8e8e8;
        margin: 0;
        padding: 40px;
        line-height: 1.6;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }}
    th {{
        text-align: left;
        padding: 10px 12px;
        color: #666;
        font-size: 10px;
        letter-spacing: 0.5px;
        border-bottom: 1px solid #2d2d2d;
    }}
</style>
</head>
<body>
<div style="max-width:900px;margin:0 auto;">
    <div style="text-align:center;margin-bottom:40px;">
        <h1 style="color:#dc2626;font-size:28px;letter-spacing:6px;margin-bottom:4px;">CEREBERUS</h1>
        <div style="color:#666;font-size:11px;letter-spacing:3px;">SECURITY ASSESSMENT REPORT</div>
        <div style="color:#666;font-size:11px;margin-top:8px;">Generated: {generated_at}</div>
    </div>

    {body}

    <div style="text-align:center;margin-top:40px;padding-top:20px;border-top:1px solid #2d2d2d;color:#666;font-size:11px;">
        CEREBERUS &mdash; AI-Powered Cybersecurity Defense System
    </div>
</div>
</body>
</html>"""
