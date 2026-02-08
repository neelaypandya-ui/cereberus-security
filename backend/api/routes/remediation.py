"""Remediation routes — execute actions, manage quarantine vault."""

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ...dependencies import get_db
from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_EXECUTE_REMEDIATION
from ...models.remediation_action import RemediationAction
from ...models.quarantine_vault import QuarantineEntry
from ...utils.input_validators import (
    validate_ip_address,
    validate_process_target,
    validate_file_path,
    validate_interface_name,
    validate_username,
)

router = APIRouter(prefix="/remediation", tags=["remediation"])

_remediation_engine = None


def _get_remediation_engine():
    from ...engine.remediation import RemediationEngine
    from ...dependencies import get_app_config
    from ...database import get_session_factory

    global _remediation_engine
    if _remediation_engine is None:
        config = get_app_config()
        factory = get_session_factory(config)
        _remediation_engine = RemediationEngine(
            db_session_factory=factory,
            base_dir=str(config.data_dir) if hasattr(config, "data_dir") else ".",
        )
    return _remediation_engine


# --- Enums ---

class ActionType(str, Enum):
    block_ip = "block_ip"
    kill_process = "kill_process"
    quarantine_file = "quarantine_file"
    isolate_network = "isolate_network"
    disable_user = "disable_user"
    block_port = "block_port"
    disable_guest = "disable_guest"
    enable_firewall = "enable_firewall"
    disable_autologin = "disable_autologin"


# --- Request bodies ---

class ExecuteActionRequest(BaseModel):
    action_type: ActionType
    target: str = Field(min_length=1, max_length=500)
    parameters: Optional[dict] = None
    incident_id: Optional[int] = Field(default=None, ge=1)


# --- Endpoints ---

@router.post("/execute", status_code=201)
async def execute_remediation_action(
    body: ExecuteActionRequest,
    current_user: dict = Depends(require_permission(PERM_EXECUTE_REMEDIATION)),
):
    """Execute a remediation action (block IP, kill process, quarantine file, etc.)."""
    # Per-action-type input validation
    try:
        if body.action_type == ActionType.block_ip:
            validate_ip_address(body.target)
        elif body.action_type == ActionType.kill_process:
            validate_process_target(body.target)
        elif body.action_type == ActionType.quarantine_file:
            validate_file_path(body.target)
        elif body.action_type == ActionType.isolate_network:
            validate_interface_name(body.target)
        elif body.action_type == ActionType.disable_user:
            validate_username(body.target)
        elif body.action_type == ActionType.block_port:
            port_val = int(body.target)
            if port_val < 1 or port_val > 65535:
                raise ValueError(f"Port must be between 1 and 65535, got: {port_val}")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    engine = _get_remediation_engine()
    actor = current_user.get("sub", "unknown")
    params = body.parameters or {}

    if body.action_type == ActionType.block_ip:
        result = await engine.block_ip(
            ip=body.target,
            duration=params.get("duration", 3600),
            reason=params.get("reason", "Manual remediation"),
            incident_id=body.incident_id,
            executed_by=actor,
        )
    elif body.action_type == ActionType.kill_process:
        result = await engine.kill_process(
            target=body.target,
            incident_id=body.incident_id,
            executed_by=actor,
        )
    elif body.action_type == ActionType.quarantine_file:
        result = await engine.quarantine_file(
            path=body.target,
            reason=params.get("reason", "Manual quarantine"),
            incident_id=body.incident_id,
            executed_by=actor,
        )
    elif body.action_type == ActionType.isolate_network:
        result = await engine.isolate_network(
            interface=body.target,
            incident_id=body.incident_id,
            executed_by=actor,
        )
    elif body.action_type == ActionType.disable_user:
        result = await engine.disable_user_account(
            username=body.target,
            incident_id=body.incident_id,
            executed_by=actor,
        )
    elif body.action_type == ActionType.block_port:
        result = await engine.block_port(
            port=int(body.target),
            protocol=params.get("protocol", "TCP"),
            incident_id=body.incident_id,
            executed_by=actor,
        )
    elif body.action_type == ActionType.disable_guest:
        result = await engine.disable_guest_account(
            incident_id=body.incident_id,
            executed_by=actor,
        )
    elif body.action_type == ActionType.enable_firewall:
        result = await engine.enable_firewall(
            incident_id=body.incident_id,
            executed_by=actor,
        )
    elif body.action_type == ActionType.disable_autologin:
        result = await engine.disable_autologin(
            incident_id=body.incident_id,
            executed_by=actor,
        )

    if not result.get("success", False) and "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])

    return result


@router.get("/actions")
async def list_remediation_actions(
    limit: int = Query(50, ge=1, le=500),
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List remediation actions with optional status filter."""
    query = select(RemediationAction).order_by(desc(RemediationAction.created_at)).limit(limit)
    if status:
        valid_statuses = ("pending", "executing", "completed", "failed", "rolled_back")
        if status not in valid_statuses:
            raise HTTPException(
                status_code=400,
                detail=f"status must be one of: {', '.join(valid_statuses)}",
            )
        query = query.where(RemediationAction.status == status)

    result = await db.execute(query)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "incident_id": r.incident_id,
            "playbook_rule_id": r.playbook_rule_id,
            "action_type": r.action_type,
            "target": r.target,
            "parameters": json.loads(r.parameters_json) if r.parameters_json else {},
            "status": r.status,
            "executed_at": r.executed_at.isoformat() if r.executed_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "result": json.loads(r.result_json) if r.result_json else {},
            "executed_by": r.executed_by,
            "rollback_data": json.loads(r.rollback_data_json) if r.rollback_data_json else {},
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.get("/actions/{action_id}")
async def get_remediation_action(
    action_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a single remediation action by ID."""
    result = await db.execute(
        select(RemediationAction).where(RemediationAction.id == action_id)
    )
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Remediation action not found")

    return {
        "id": action.id,
        "incident_id": action.incident_id,
        "playbook_rule_id": action.playbook_rule_id,
        "action_type": action.action_type,
        "target": action.target,
        "parameters": json.loads(action.parameters_json) if action.parameters_json else {},
        "status": action.status,
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
        "completed_at": action.completed_at.isoformat() if action.completed_at else None,
        "result": json.loads(action.result_json) if action.result_json else {},
        "executed_by": action.executed_by,
        "rollback_data": json.loads(action.rollback_data_json) if action.rollback_data_json else {},
        "created_at": action.created_at.isoformat() if action.created_at else None,
    }


@router.post("/actions/{action_id}/rollback")
async def rollback_remediation_action(
    action_id: int,
    current_user: dict = Depends(require_permission(PERM_EXECUTE_REMEDIATION)),
):
    """Rollback a previously executed remediation action."""
    engine = _get_remediation_engine()
    actor = current_user.get("sub", "unknown")
    result = await engine.rollback_action(action_id=action_id, executed_by=actor)

    if not result.get("success", False):
        error = result.get("error", "Rollback failed")
        if "not found" in error.lower():
            raise HTTPException(status_code=404, detail=error)
        raise HTTPException(status_code=400, detail=error)

    return result


@router.get("/quarantine")
async def list_quarantined_files(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all quarantined files."""
    result = await db.execute(
        select(QuarantineEntry).order_by(desc(QuarantineEntry.quarantined_at))
    )
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "original_path": r.original_path,
            "vault_path": r.vault_path,
            "file_hash": r.file_hash,
            "file_size": r.file_size,
            "quarantined_at": r.quarantined_at.isoformat() if r.quarantined_at else None,
            "quarantined_by": r.quarantined_by,
            "reason": r.reason,
            "incident_id": r.incident_id,
            "restored_at": r.restored_at.isoformat() if r.restored_at else None,
            "status": r.status,
        }
        for r in rows
    ]


@router.post("/quarantine/{quarantine_id}/restore")
async def restore_quarantined_file(
    quarantine_id: int,
    current_user: dict = Depends(require_permission(PERM_EXECUTE_REMEDIATION)),
):
    """Restore a quarantined file to its original location."""
    engine = _get_remediation_engine()
    actor = current_user.get("sub", "unknown")
    result = await engine.restore_file(quarantine_id=quarantine_id, executed_by=actor)

    if not result.get("success", False):
        error = result.get("error", "Restore failed")
        if "not found" in error.lower():
            raise HTTPException(status_code=404, detail=error)
        raise HTTPException(status_code=400, detail=error)

    return result


@router.delete("/quarantine/{quarantine_id}")
async def delete_quarantined_file(
    quarantine_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_EXECUTE_REMEDIATION)),
):
    """Permanently delete a quarantined file from the vault."""
    result = await db.execute(
        select(QuarantineEntry).where(QuarantineEntry.id == quarantine_id)
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Quarantine entry not found")

    if entry.status == "restored":
        raise HTTPException(status_code=400, detail="Cannot delete a restored entry; file is no longer in vault")

    # Delete the vault file from disk
    import os
    from pathlib import Path
    vault_path = Path(entry.vault_path)
    if vault_path.exists():
        try:
            os.remove(str(vault_path))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to delete vault file: {e}")

    entry.status = "deleted"
    await db.commit()

    return {"id": quarantine_id, "status": "deleted", "original_path": entry.original_path}
