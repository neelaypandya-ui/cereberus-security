"""HTML report template for security assessment reports."""

from datetime import datetime, timezone


def render_report(data: dict) -> str:
    """Render a security assessment report as HTML.

    Args:
        data: Dict with keys: threat_level, alerts, vulnerabilities, modules,
              resources, recommendations, generated_at.

    Returns:
        Complete HTML string.
    """
    generated_at = data.get("generated_at", datetime.now(timezone.utc).isoformat())
    threat_level = data.get("threat_level", "none")
    alerts = data.get("alerts", [])
    vulnerabilities = data.get("vulnerabilities", [])
    modules = data.get("modules", [])
    resources = data.get("resources", {})
    recommendations = data.get("recommendations", [])

    severity_counts = {}
    for a in alerts:
        sev = a.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    threat_color = {
        "none": "#4caf50", "low": "#2196f3", "medium": "#ff9800",
        "high": "#ff5722", "critical": "#ff1744",
    }.get(threat_level, "#666")

    alert_rows = ""
    for a in alerts[:50]:
        sev = a.get("severity", "info")
        sev_color = {"critical": "#ff1744", "high": "#ff5722", "medium": "#ff9800", "low": "#ffc107", "info": "#2196f3"}.get(sev, "#666")
        alert_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">
                <span style="color:{sev_color};font-weight:700;text-transform:uppercase;">{sev}</span>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">{a.get('title','')}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;color:#666;">{a.get('module_source','')}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;color:#666;">{a.get('timestamp','')}</td>
        </tr>"""

    vuln_rows = ""
    for v in vulnerabilities[:30]:
        sev = v.get("severity", "info")
        sev_color = {"critical": "#ff1744", "high": "#ff5722", "medium": "#ff9800"}.get(sev, "#666")
        vuln_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">
                <span style="color:{sev_color};font-weight:700;text-transform:uppercase;">{sev}</span>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">{v.get('title','')}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;color:#a0a0a0;">{v.get('description','')[:120]}</td>
        </tr>"""

    module_rows = ""
    for m in modules:
        status_color = "#4caf50" if m.get("health") == "running" else "#f44336"
        module_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">{m.get('name','')}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;">
                <span style="color:{status_color};">{'Enabled' if m.get('enabled') else 'Disabled'}</span>
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #2d2d2d;color:{status_color};">{m.get('health','')}</td>
        </tr>"""

    rec_items = ""
    for r in recommendations:
        rec_items += f'<li style="margin-bottom:8px;color:#a0a0a0;">{r}</li>'

    resource_section = ""
    if resources:
        resource_section = f"""
        <h2 style="color:#00e5ff;font-size:16px;margin-top:32px;margin-bottom:12px;letter-spacing:2px;">SYSTEM RESOURCES</h2>
        <div style="display:flex;gap:24px;flex-wrap:wrap;">
            <div style="background:#1a1a1a;padding:16px 24px;border-radius:8px;border:1px solid #2d2d2d;">
                <div style="color:#666;font-size:10px;letter-spacing:1px;">CPU</div>
                <div style="font-size:24px;font-weight:700;color:#e8e8e8;">{resources.get('cpu_percent', 'N/A')}%</div>
            </div>
            <div style="background:#1a1a1a;padding:16px 24px;border-radius:8px;border:1px solid #2d2d2d;">
                <div style="color:#666;font-size:10px;letter-spacing:1px;">MEMORY</div>
                <div style="font-size:24px;font-weight:700;color:#e8e8e8;">{resources.get('memory_percent', 'N/A')}%</div>
            </div>
            <div style="background:#1a1a1a;padding:16px 24px;border-radius:8px;border:1px solid #2d2d2d;">
                <div style="color:#666;font-size:10px;letter-spacing:1px;">DISK</div>
                <div style="font-size:24px;font-weight:700;color:#e8e8e8;">{resources.get('disk_percent', 'N/A')}%</div>
            </div>
        </div>"""

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

    <h2 style="color:#00e5ff;font-size:16px;margin-bottom:12px;letter-spacing:2px;">EXECUTIVE SUMMARY</h2>
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
    </div>

    <h2 style="color:#00e5ff;font-size:16px;margin-top:32px;margin-bottom:12px;letter-spacing:2px;">ALERT SUMMARY</h2>
    <div style="background:#161616;border-radius:8px;border:1px solid #2d2d2d;overflow:auto;">
        <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Source</th><th>Time</th></tr></thead>
            <tbody>{alert_rows if alert_rows else '<tr><td colspan="4" style="padding:20px;text-align:center;color:#666;">No alerts</td></tr>'}</tbody>
        </table>
    </div>

    <h2 style="color:#00e5ff;font-size:16px;margin-top:32px;margin-bottom:12px;letter-spacing:2px;">VULNERABILITY FINDINGS</h2>
    <div style="background:#161616;border-radius:8px;border:1px solid #2d2d2d;overflow:auto;">
        <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Description</th></tr></thead>
            <tbody>{vuln_rows if vuln_rows else '<tr><td colspan="3" style="padding:20px;text-align:center;color:#666;">No vulnerabilities found</td></tr>'}</tbody>
        </table>
    </div>

    <h2 style="color:#00e5ff;font-size:16px;margin-top:32px;margin-bottom:12px;letter-spacing:2px;">MODULE HEALTH</h2>
    <div style="background:#161616;border-radius:8px;border:1px solid #2d2d2d;overflow:auto;">
        <table>
            <thead><tr><th>Module</th><th>Status</th><th>Health</th></tr></thead>
            <tbody>{module_rows if module_rows else '<tr><td colspan="3" style="padding:20px;text-align:center;color:#666;">No modules</td></tr>'}</tbody>
        </table>
    </div>

    {resource_section}

    <h2 style="color:#00e5ff;font-size:16px;margin-top:32px;margin-bottom:12px;letter-spacing:2px;">RECOMMENDATIONS</h2>
    <div style="background:#161616;padding:20px;border-radius:8px;border:1px solid #2d2d2d;">
        <ul style="padding-left:20px;">{rec_items if rec_items else '<li style="color:#666;">No specific recommendations at this time.</li>'}</ul>
    </div>

    <div style="text-align:center;margin-top:40px;padding-top:20px;border-top:1px solid #2d2d2d;color:#666;font-size:11px;">
        CEREBERUS &mdash; AI-Powered Cybersecurity Defense System
    </div>
</div>
</body>
</html>"""
