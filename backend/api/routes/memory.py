"""Memory scanner routes — Bond's reconnaissance operations."""

import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_MANAGE_SETTINGS
from ...bridge import validate_and_log, MemoryScanResultResponse
from ...dependencies import get_memory_scanner, get_db

router = APIRouter(prefix="/memory", tags=["memory"])


@router.get("/status")
async def get_memory_status(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get memory scanner status."""
    scanner = get_memory_scanner()
    return scanner.get_status()


@router.get("/results")
async def get_memory_results(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get memory scan results from DB."""
    from ...models.memory_scan_result import MemoryScanResult
    result = await db.execute(
        select(MemoryScanResult).order_by(MemoryScanResult.id.desc()).offset(offset).limit(limit)
    )
    results = result.scalars().all()
    data = [
        {
            "id": r.id,
            "pid": r.pid,
            "process_name": r.process_name,
            "finding_type": r.finding_type,
            "severity": r.severity,
            "details": json.loads(r.details_json) if r.details_json else {},
            "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
        }
        for r in results
    ]
    return validate_and_log(data, MemoryScanResultResponse, "GET /memory/results")


@router.post("/scan")
async def trigger_full_scan(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Trigger a full memory scan of all processes."""
    scanner = get_memory_scanner()
    if not scanner.running:
        raise HTTPException(status_code=503, detail="Memory scanner not running")
    import asyncio
    asyncio.create_task(scanner._run_scan())
    return {"status": "SCAN_INITIATED", "message": "Reconnaissance underway..."}


@router.post("/scan/{pid}")
async def scan_process(
    pid: int,
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Scan a specific process by PID."""
    scanner = get_memory_scanner()
    findings = await scanner.scan_process(pid)
    return {"pid": pid, "findings": len(findings), "results": findings}


@router.get("/scan/{pid}/regions")
async def get_process_regions(
    pid: int,
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get memory regions for a specific process."""
    scanner = get_memory_scanner()
    regions = await scanner.get_process_regions(pid)
    return {"pid": pid, "regions": regions, "count": len(regions)}
