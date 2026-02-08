"""Commander Bond threat intelligence operative routes."""

from fastapi import APIRouter, Depends, HTTPException, Query

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_MANAGE_SETTINGS
from ...dependencies import get_commander_bond

router = APIRouter(prefix="/bond", tags=["bond"])


@router.get("/status")
async def get_bond_status(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get Bond's operational status."""
    bond = get_commander_bond()
    status = bond.get_status()
    return status


@router.get("/reports")
async def get_bond_reports(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get all intelligence reports."""
    bond = get_commander_bond()
    return bond.get_reports()


@router.get("/reports/{report_id}")
async def get_bond_report(
    report_id: str,
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a specific intelligence report."""
    bond = get_commander_bond()
    reports = bond.get_reports()
    for r in reports:
        if r.get("id") == report_id:
            return r
    raise HTTPException(status_code=404, detail="Report not found")


@router.get("/latest")
async def get_bond_latest(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get the most recent intelligence report."""
    bond = get_commander_bond()
    latest = bond.get_latest_report()
    if not latest:
        return {"status": "NO INTELLIGENCE GATHERED", "threats": [], "threat_count": 0}
    return latest


@router.post("/scan")
async def trigger_bond_scan(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Deploy Bond into the field — trigger immediate scan."""
    bond = get_commander_bond()
    if not bond.running:
        raise HTTPException(status_code=503, detail="Bond is offline")
    import asyncio
    asyncio.create_task(bond._execute_scan())
    return {"status": "DEPLOYED", "message": "Bond is in the field..."}


@router.get("/threats")
async def get_bond_threats(
    category: str | None = None,
    severity: str | None = None,
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get all threats across reports, filterable by category/severity."""
    bond = get_commander_bond()
    return bond.get_all_threats(category=category, severity=severity)


@router.post("/threats/{threat_id}/neutralize")
async def neutralize_threat(
    threat_id: str,
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Mark a threat as neutralized — removes it from all Bond responses."""
    bond = get_commander_bond()
    found = bond.neutralize_threat(threat_id)
    if not found:
        raise HTTPException(status_code=404, detail="Threat not found in any report")
    return {"status": "NEUTRALIZED", "threat_id": threat_id, "message": "Target eliminated."}


@router.post("/threats/neutralize-all")
async def neutralize_all_threats(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Mark all current threats as neutralized."""
    bond = get_commander_bond()
    count = bond.neutralize_all()
    return {"status": "ALL NEUTRALIZED", "count": count, "message": "All targets eliminated."}
