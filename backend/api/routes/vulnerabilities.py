"""Vulnerability Scanner API routes."""

from fastapi import APIRouter, Depends

from ...dependencies import get_current_user, get_vuln_scanner

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("/")
async def get_vulnerabilities(current_user: dict = Depends(get_current_user)):
    """Get all discovered vulnerabilities."""
    scanner = get_vuln_scanner()
    return scanner.get_vulnerabilities()


@router.post("/scan")
async def trigger_scan(current_user: dict = Depends(get_current_user)):
    """Trigger a new vulnerability scan."""
    scanner = get_vuln_scanner()
    report = await scanner.run_scan()
    return report


@router.get("/report")
async def get_report(current_user: dict = Depends(get_current_user)):
    """Get the last scan report."""
    scanner = get_vuln_scanner()
    report = scanner.get_last_report()
    return report or {"total_findings": 0, "vulnerabilities": []}
