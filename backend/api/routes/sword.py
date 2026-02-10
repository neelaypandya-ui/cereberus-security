"""Sword Protocol routes — Bond's autonomous response management."""

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_MANAGE_SETTINGS
from ...bridge import validate_and_log, SwordPolicyResponse, SwordLogResponse
from ...dependencies import get_commander_bond, get_db

router = APIRouter(prefix="/bond/sword", tags=["sword"])


# --- Request models ---

class CreateSwordPolicyRequest(BaseModel):
    codename: str
    name: str
    description: Optional[str] = None
    trigger_type: str = ""
    trigger_conditions: dict = {}
    escalation_chain: list = []
    cooldown_seconds: int = 300
    rate_limit: Optional[dict] = None
    enabled: bool = True
    requires_confirmation: bool = False


class UpdateSwordPolicyRequest(BaseModel):
    codename: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_conditions: Optional[dict] = None
    escalation_chain: Optional[list] = None
    cooldown_seconds: Optional[int] = None
    rate_limit: Optional[dict] = None
    enabled: Optional[bool] = None
    requires_confirmation: Optional[bool] = None


class TestSwordPolicyRequest(BaseModel):
    test: bool = True
    severity: str = "critical"
    module_source: str = "test"


# --- Policy CRUD ---

@router.get("/policies")
async def list_sword_policies(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all Sword Protocol policies."""
    from ...models.sword_policy import SwordPolicy
    result = await db.execute(select(SwordPolicy).order_by(SwordPolicy.id))
    policies = result.scalars().all()
    data = [
        {
            "id": p.id,
            "codename": p.codename,
            "name": p.name,
            "description": p.description,
            "trigger_type": p.trigger_type,
            "trigger_conditions": json.loads(p.trigger_conditions_json) if p.trigger_conditions_json else {},
            "escalation_chain": json.loads(p.escalation_chain_json) if p.escalation_chain_json else [],
            "cooldown_seconds": p.cooldown_seconds,
            "rate_limit": json.loads(p.rate_limit_json) if p.rate_limit_json else None,
            "enabled": p.enabled,
            "requires_confirmation": p.requires_confirmation,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "last_triggered": p.last_triggered.isoformat() if p.last_triggered else None,
            "execution_count": p.execution_count,
        }
        for p in policies
    ]
    return validate_and_log(data, SwordPolicyResponse, "GET /bond/sword/policies")


@router.post("/policies")
async def create_sword_policy(
    data: CreateSwordPolicyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Create a new Sword Protocol policy."""
    from ...models.sword_policy import SwordPolicy
    if not data.codename.strip() or not data.name.strip():
        raise HTTPException(status_code=400, detail="codename and name are required")

    policy = SwordPolicy(
        codename=data.codename.strip(),
        name=data.name.strip(),
        description=data.description,
        trigger_type=data.trigger_type,
        trigger_conditions_json=json.dumps(data.trigger_conditions),
        escalation_chain_json=json.dumps(data.escalation_chain),
        cooldown_seconds=data.cooldown_seconds,
        rate_limit_json=json.dumps(data.rate_limit) if data.rate_limit else None,
        enabled=data.enabled,
        requires_confirmation=data.requires_confirmation,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return {"id": policy.id, "codename": policy.codename, "status": "created"}


@router.get("/policies/{policy_id}")
async def get_sword_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a specific Sword Protocol policy."""
    from ...models.sword_policy import SwordPolicy
    result = await db.execute(select(SwordPolicy).where(SwordPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {
        "id": policy.id,
        "codename": policy.codename,
        "name": policy.name,
        "description": policy.description,
        "trigger_type": policy.trigger_type,
        "trigger_conditions": json.loads(policy.trigger_conditions_json) if policy.trigger_conditions_json else {},
        "escalation_chain": json.loads(policy.escalation_chain_json) if policy.escalation_chain_json else [],
        "cooldown_seconds": policy.cooldown_seconds,
        "enabled": policy.enabled,
        "requires_confirmation": policy.requires_confirmation,
        "execution_count": policy.execution_count,
    }


@router.put("/policies/{policy_id}")
async def update_sword_policy(
    policy_id: int,
    data: UpdateSwordPolicyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Update a Sword Protocol policy."""
    from ...models.sword_policy import SwordPolicy
    result = await db.execute(select(SwordPolicy).where(SwordPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if data.codename is not None:
        policy.codename = data.codename
    if data.name is not None:
        policy.name = data.name
    if data.description is not None:
        policy.description = data.description
    if data.trigger_type is not None:
        policy.trigger_type = data.trigger_type
    if data.cooldown_seconds is not None:
        policy.cooldown_seconds = data.cooldown_seconds
    if data.enabled is not None:
        policy.enabled = data.enabled
    if data.requires_confirmation is not None:
        policy.requires_confirmation = data.requires_confirmation
    if data.trigger_conditions is not None:
        policy.trigger_conditions_json = json.dumps(data.trigger_conditions)
    if data.escalation_chain is not None:
        policy.escalation_chain_json = json.dumps(data.escalation_chain)
    if data.rate_limit is not None:
        policy.rate_limit_json = json.dumps(data.rate_limit)

    await db.commit()
    return {"status": "updated", "id": policy_id}


@router.delete("/policies/{policy_id}")
async def delete_sword_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Delete a Sword Protocol policy."""
    from ...models.sword_policy import SwordPolicy
    result = await db.execute(select(SwordPolicy).where(SwordPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    await db.delete(policy)
    await db.commit()
    return {"status": "deleted", "id": policy_id}


@router.patch("/policies/{policy_id}/toggle")
async def toggle_sword_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Toggle a policy on/off."""
    from ...models.sword_policy import SwordPolicy
    result = await db.execute(select(SwordPolicy).where(SwordPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.enabled = not policy.enabled
    await db.commit()
    return {"status": "toggled", "id": policy_id, "enabled": policy.enabled}


# --- Execution log ---

@router.get("/logs")
async def get_sword_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get Sword Protocol execution log."""
    from ...models.sword_execution_log import SwordExecutionLog
    result = await db.execute(
        select(SwordExecutionLog).order_by(SwordExecutionLog.id.desc()).offset(offset).limit(limit)
    )
    logs = result.scalars().all()
    data = [
        {
            "id": l.id,
            "policy_id": l.policy_id,
            "codename": l.codename,
            "trigger_event": json.loads(l.trigger_event_json) if l.trigger_event_json else {},
            "actions_taken": json.loads(l.actions_taken_json) if l.actions_taken_json else [],
            "result": l.result,
            "escalation_level": l.escalation_level,
            "executed_at": l.executed_at.isoformat() if l.executed_at else None,
            "duration_ms": l.duration_ms,
        }
        for l in logs
    ]
    return validate_and_log(data, SwordLogResponse, "GET /bond/sword/logs")


@router.get("/stats")
async def get_sword_stats(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get Sword Protocol stats from Bond."""
    bond = get_commander_bond()
    return bond.get_sword_stats()


# --- Control ---

@router.post("/enable")
async def enable_sword(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Enable Sword Protocol — Bond draws the sword."""
    bond = get_commander_bond()
    bond.sword_enable()
    return {"status": "enabled", "message": "The sword is drawn."}


@router.post("/disable")
async def disable_sword(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Disable Sword Protocol — Bond sheathes the sword."""
    bond = get_commander_bond()
    bond.sword_disable()
    return {"status": "disabled", "message": "The sword is sheathed."}


@router.post("/lockout")
async def sword_lockout(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Emergency lockout — no autonomous actions."""
    bond = get_commander_bond()
    bond.sword_lockout()
    return {"status": "lockout", "message": "Emergency lockout engaged."}


@router.post("/clear")
async def sword_clear_lockout(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Clear lockout — restore autonomous capability."""
    bond = get_commander_bond()
    bond.sword_clear_lockout()
    return {"status": "cleared", "message": "Lockout cleared. Sword Protocol operational."}


@router.post("/test/{policy_id}")
async def test_sword_policy(
    policy_id: int,
    data: TestSwordPolicyRequest | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Dry-run a policy — evaluate without striking."""
    from ...models.sword_policy import SwordPolicy
    result = await db.execute(select(SwordPolicy).where(SwordPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    bond = get_commander_bond()
    test_event = data.model_dump() if data else {"test": True, "severity": "critical", "module_source": "test"}
    evaluation = bond.sword_test_policy(policy_id, test_event)
    return {"policy_id": policy_id, "codename": policy.codename, "evaluation": evaluation}
