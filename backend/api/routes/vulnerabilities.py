"""Vulnerability Scanner API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_EXECUTE_REMEDIATION
from ...dependencies import get_vuln_scanner

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


class RemediateRequest(BaseModel):
    category: str
    port: Optional[int] = None
    service: Optional[str] = None


@router.get("/")
async def get_vulnerabilities(current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD))):
    """Get all discovered vulnerabilities."""
    scanner = get_vuln_scanner()
    return scanner.get_vulnerabilities()


@router.post("/scan")
async def trigger_scan(current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD))):
    """Trigger a new vulnerability scan."""
    scanner = get_vuln_scanner()
    report = await scanner.run_scan()
    return report


@router.get("/report")
async def get_report(current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD))):
    """Get the last scan report."""
    scanner = get_vuln_scanner()
    report = scanner.get_last_report()
    return report or {"total_findings": 0, "vulnerabilities": []}


@router.post("/remediate")
async def remediate_vulnerability(
    body: RemediateRequest,
    current_user: dict = Depends(require_permission(PERM_EXECUTE_REMEDIATION)),
):
    """Remediate a vulnerability by category."""
    from ...engine.remediation import RemediationEngine
    from ...dependencies import get_app_config
    from ...database import get_session_factory

    config = get_app_config()
    factory = get_session_factory(config)
    engine = RemediationEngine(db_session_factory=factory, base_dir=str(config.data_dir) if hasattr(config, "data_dir") else ".")

    actor = current_user.get("sub", "unknown")

    if body.category == "open_port":
        if not body.port:
            raise HTTPException(status_code=400, detail="port is required for open_port remediation")
        result = await engine.block_port(port=body.port, executed_by=actor)
    elif body.category == "guest_account":
        result = await engine.disable_guest_account(executed_by=actor)
    elif body.category == "firewall":
        result = await engine.enable_firewall(executed_by=actor)
    elif body.category == "autologin":
        result = await engine.disable_autologin(executed_by=actor)
    elif body.category == "windows_update":
        return {
            "success": False,
            "manual": True,
            "message": "Windows Update remediation requires manual intervention. Open Settings > Update & Security > Windows Update and install pending updates. Auto-patching is unsafe as it may require reboots and could cause compatibility issues.",
        }
    else:
        raise HTTPException(status_code=400, detail=f"Unknown vulnerability category: {body.category}")

    # Always return the result — let the frontend display success/failure details
    # The engine already persists the action status to the DB
    return result
