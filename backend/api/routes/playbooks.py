"""Playbook management routes — CRUD and execution of automated response rules."""

import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ...dependencies import get_db
from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_MANAGE_PLAYBOOKS
from ...models.playbook_rule import PlaybookRule
from ...models.remediation_action import RemediationAction

router = APIRouter(prefix="/playbooks", tags=["playbooks"])

_playbook_executor = None


def _get_playbook_executor():
    from ...engine.playbook_executor import PlaybookExecutor
    from ...dependencies import get_app_config
    from ...database import get_session_factory

    global _playbook_executor
    if _playbook_executor is None:
        config = get_app_config()
        factory = get_session_factory(config)
        _playbook_executor = PlaybookExecutor(db_session_factory=factory)
    return _playbook_executor


# --- Request bodies ---

class CreatePlaybookRuleRequest(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_type: str  # alert_severity, anomaly_score, threat_level, correlation_pattern, module_event
    trigger_conditions: dict = {}
    actions: list[dict] = []
    cooldown_seconds: int = 300
    requires_confirmation: bool = False


class UpdatePlaybookRuleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_conditions: Optional[dict] = None
    actions: Optional[list[dict]] = None
    cooldown_seconds: Optional[int] = None
    requires_confirmation: Optional[bool] = None


class ExecutePlaybookRequest(BaseModel):
    event_context: dict = {}


class DryRunRequest(BaseModel):
    event_context: dict = {}


# --- Helpers ---

def _rule_to_response(rule: PlaybookRule) -> dict:
    """Convert a PlaybookRule ORM object to a response dict."""
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "enabled": rule.enabled,
        "trigger_type": rule.trigger_type,
        "trigger_conditions": json.loads(rule.trigger_conditions_json) if rule.trigger_conditions_json else {},
        "actions": json.loads(rule.actions_json) if rule.actions_json else [],
        "cooldown_seconds": rule.cooldown_seconds,
        "last_triggered": rule.last_triggered.isoformat() if rule.last_triggered else None,
        "execution_count": rule.execution_count,
        "requires_confirmation": rule.requires_confirmation,
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
    }


# --- Endpoints ---

@router.get("/")
async def list_playbook_rules(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all playbook rules."""
    result = await db.execute(
        select(PlaybookRule).order_by(desc(PlaybookRule.created_at))
    )
    rows = result.scalars().all()
    return [_rule_to_response(r) for r in rows]


@router.post("/", status_code=201)
async def create_playbook_rule(
    body: CreatePlaybookRuleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_PLAYBOOKS)),
):
    """Create a new playbook rule."""
    valid_trigger_types = (
        "alert_severity", "anomaly_score", "threat_level",
        "correlation_pattern", "module_event",
    )
    if body.trigger_type not in valid_trigger_types:
        raise HTTPException(
            status_code=400,
            detail=f"trigger_type must be one of: {', '.join(valid_trigger_types)}",
        )

    # Check for duplicate name
    existing = await db.execute(
        select(PlaybookRule).where(PlaybookRule.name == body.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"A playbook rule named '{body.name}' already exists")

    rule = PlaybookRule(
        name=body.name,
        description=body.description,
        trigger_type=body.trigger_type,
        trigger_conditions_json=json.dumps(body.trigger_conditions),
        actions_json=json.dumps(body.actions),
        cooldown_seconds=body.cooldown_seconds,
        requires_confirmation=body.requires_confirmation,
        created_by=current_user.get("sub", "unknown"),
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _rule_to_response(rule)


@router.get("/{rule_id}")
async def get_playbook_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a single playbook rule by ID."""
    result = await db.execute(
        select(PlaybookRule).where(PlaybookRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Playbook rule not found")
    return _rule_to_response(rule)


@router.put("/{rule_id}")
async def update_playbook_rule(
    rule_id: int,
    body: UpdatePlaybookRuleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_PLAYBOOKS)),
):
    """Update a playbook rule."""
    result = await db.execute(
        select(PlaybookRule).where(PlaybookRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Playbook rule not found")

    if body.name is not None:
        # Check for duplicate name (excluding current rule)
        dup_check = await db.execute(
            select(PlaybookRule).where(
                PlaybookRule.name == body.name,
                PlaybookRule.id != rule_id,
            )
        )
        if dup_check.scalar_one_or_none():
            raise HTTPException(status_code=409, detail=f"A playbook rule named '{body.name}' already exists")
        rule.name = body.name

    if body.description is not None:
        rule.description = body.description
    if body.trigger_type is not None:
        valid_trigger_types = (
            "alert_severity", "anomaly_score", "threat_level",
            "correlation_pattern", "module_event",
        )
        if body.trigger_type not in valid_trigger_types:
            raise HTTPException(
                status_code=400,
                detail=f"trigger_type must be one of: {', '.join(valid_trigger_types)}",
            )
        rule.trigger_type = body.trigger_type
    if body.trigger_conditions is not None:
        rule.trigger_conditions_json = json.dumps(body.trigger_conditions)
    if body.actions is not None:
        rule.actions_json = json.dumps(body.actions)
    if body.cooldown_seconds is not None:
        rule.cooldown_seconds = body.cooldown_seconds
    if body.requires_confirmation is not None:
        rule.requires_confirmation = body.requires_confirmation

    await db.commit()
    await db.refresh(rule)
    return _rule_to_response(rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_playbook_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_PLAYBOOKS)),
):
    """Delete a playbook rule."""
    result = await db.execute(
        select(PlaybookRule).where(PlaybookRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Playbook rule not found")

    await db.delete(rule)
    await db.commit()
    return None


@router.patch("/{rule_id}/toggle")
async def toggle_playbook_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_PLAYBOOKS)),
):
    """Toggle a playbook rule enabled/disabled."""
    result = await db.execute(
        select(PlaybookRule).where(PlaybookRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Playbook rule not found")

    rule.enabled = not rule.enabled
    await db.commit()
    await db.refresh(rule)
    return _rule_to_response(rule)


@router.post("/{rule_id}/execute")
async def execute_playbook_rule(
    rule_id: int,
    body: ExecutePlaybookRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_PLAYBOOKS)),
):
    """Manually execute a playbook rule with provided event context."""
    executor = _get_playbook_executor()
    result = await executor.execute_playbook(
        rule_id=rule_id,
        event_context=body.event_context,
        dry_run=False,
    )
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/{rule_id}/dry-run")
async def dry_run_playbook_rule(
    rule_id: int,
    body: DryRunRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_PLAYBOOKS)),
):
    """Dry-run a playbook rule to preview actions without executing."""
    executor = _get_playbook_executor()
    result = await executor.execute_playbook(
        rule_id=rule_id,
        event_context=body.event_context,
        dry_run=True,
    )
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/{rule_id}/history")
async def get_playbook_history(
    rule_id: int,
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get remediation actions triggered by a specific playbook rule."""
    # Verify the rule exists
    rule_result = await db.execute(
        select(PlaybookRule).where(PlaybookRule.id == rule_id)
    )
    rule = rule_result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Playbook rule not found")

    result = await db.execute(
        select(RemediationAction)
        .where(RemediationAction.playbook_rule_id == rule_id)
        .order_by(desc(RemediationAction.created_at))
        .limit(limit)
    )
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
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
