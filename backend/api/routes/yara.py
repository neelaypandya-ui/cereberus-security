"""YARA scanning routes — Bond's Q-Branch arsenal management."""

import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_MANAGE_SETTINGS
from ...dependencies import get_yara_scanner, get_db
from ...utils.input_validators import validate_file_path

router = APIRouter(prefix="/yara", tags=["yara"])


# --- Request models ---

class CreateYaraRuleRequest(BaseModel):
    name: str
    rule_source: str
    description: Optional[str] = None
    enabled: bool = True
    tags: list[str] = []


class UpdateYaraRuleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rule_source: Optional[str] = None
    enabled: Optional[bool] = None
    tags: Optional[list[str]] = None


class ScanPathRequest(BaseModel):
    path: str


# --- Rule CRUD ---

@router.get("/rules")
async def list_yara_rules(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all user-managed YARA rules."""
    from ...models.yara_rule import YaraRule
    result = await db.execute(
        select(YaraRule).order_by(YaraRule.id.desc()).offset(offset).limit(limit)
    )
    rules = result.scalars().all()
    data = [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "enabled": r.enabled,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            "tags": json.loads(r.tags_json) if r.tags_json else [],
            "match_count": r.match_count,
            "last_match_at": r.last_match_at.isoformat() if r.last_match_at else None,
        }
        for r in rules
    ]
    return data


@router.post("/rules")
async def create_yara_rule(
    data: CreateYaraRuleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Create a new user-managed YARA rule."""
    from ...models.yara_rule import YaraRule
    if not data.name.strip() or not data.rule_source.strip():
        raise HTTPException(status_code=400, detail="name and rule_source are required")

    rule = YaraRule(
        name=data.name.strip(),
        description=data.description,
        rule_source=data.rule_source.strip(),
        enabled=data.enabled,
        created_by=current_user.get("sub", "unknown"),
        tags_json=json.dumps(data.tags),
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return {"id": rule.id, "name": rule.name, "status": "created"}


@router.get("/rules/{rule_id}")
async def get_yara_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a specific YARA rule with full source."""
    from ...models.yara_rule import YaraRule
    result = await db.execute(select(YaraRule).where(YaraRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "rule_source": rule.rule_source,
        "enabled": rule.enabled,
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "tags": json.loads(rule.tags_json) if rule.tags_json else [],
        "match_count": rule.match_count,
    }


@router.put("/rules/{rule_id}")
async def update_yara_rule(
    rule_id: int,
    data: UpdateYaraRuleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Update a YARA rule."""
    from ...models.yara_rule import YaraRule
    result = await db.execute(select(YaraRule).where(YaraRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if data.name is not None:
        rule.name = data.name
    if data.description is not None:
        rule.description = data.description
    if data.rule_source is not None:
        rule.rule_source = data.rule_source
    if data.enabled is not None:
        rule.enabled = data.enabled
    if data.tags is not None:
        rule.tags_json = json.dumps(data.tags)

    await db.commit()
    return {"status": "updated", "id": rule_id}


@router.delete("/rules/{rule_id}")
async def delete_yara_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Delete a YARA rule."""
    from ...models.yara_rule import YaraRule
    result = await db.execute(select(YaraRule).where(YaraRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    return {"status": "deleted", "id": rule_id}


@router.post("/rules/compile")
async def compile_rules(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Recompile all YARA rules (file + DB)."""
    scanner = get_yara_scanner()
    result = await scanner.compile_rules()
    return result


# --- Scanning ---

def _validate_scan_path(path: str) -> str:
    """Validate and resolve a scan path — reject traversal and sensitive directories."""
    path = path.strip()
    if not path:
        raise HTTPException(status_code=400, detail="path is required")
    try:
        validate_file_path(path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    resolved = Path(path).resolve()
    # Reject symlinks pointing to sensitive directories
    sensitive_prefixes = [
        r"C:\Windows\System32\config",
        r"C:\Windows\System32\drivers\etc",
    ]
    resolved_str = str(resolved)
    for prefix in sensitive_prefixes:
        if resolved_str.lower().startswith(prefix.lower()):
            raise HTTPException(status_code=400, detail="Access to sensitive system directories denied")
    return str(resolved)


@router.post("/scan/file")
async def scan_file(
    data: ScanPathRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Scan a single file with YARA rules."""
    path = _validate_scan_path(data.path)
    scanner = get_yara_scanner()
    matches = await scanner.scan_file(path, triggered_by="manual")
    return {"path": path, "matches": len(matches), "results": matches}


@router.post("/scan/directory")
async def scan_directory(
    data: ScanPathRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Recursively scan a directory with YARA rules."""
    path = _validate_scan_path(data.path)
    scanner = get_yara_scanner()
    matches = await scanner.scan_directory(path, triggered_by="manual")
    return {"path": path, "matches": len(matches), "results": matches}


@router.post("/scan/process/{pid}")
async def scan_process(
    pid: int,
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Scan a process's memory with YARA rules."""
    scanner = get_yara_scanner()
    matches = await scanner.scan_process_memory(pid, triggered_by="manual")
    return {"pid": pid, "matches": len(matches), "results": matches}


# --- Results ---

@router.get("/results")
async def get_scan_results(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get YARA scan result history."""
    from ...models.yara_scan_result import YaraScanResult
    result = await db.execute(
        select(YaraScanResult).order_by(YaraScanResult.id.desc()).offset(offset).limit(limit)
    )
    results = result.scalars().all()
    data = [
        {
            "id": r.id,
            "scan_type": r.scan_type,
            "target": r.target,
            "rule_name": r.rule_name,
            "rule_namespace": r.rule_namespace,
            "strings_matched": json.loads(r.strings_matched_json) if r.strings_matched_json else [],
            "meta": json.loads(r.meta_json) if r.meta_json else {},
            "severity": r.severity,
            "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
            "file_hash": r.file_hash,
            "file_size": r.file_size,
            "triggered_by": r.triggered_by,
        }
        for r in results
    ]
    return data


@router.get("/stats")
async def get_yara_stats(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get YARA scanner statistics."""
    scanner = get_yara_scanner()
    return scanner.get_stats()
