"""Incident management routes — full incident lifecycle CRUD and operations."""

import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ...dependencies import get_db
from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_MANAGE_INCIDENTS
from ...models.incident import Incident
from ...models.remediation_action import RemediationAction

router = APIRouter(prefix="/incidents", tags=["incidents"])

_incident_manager = None


def _get_incident_manager():
    from ...engine.incident_manager import IncidentManager
    from ...dependencies import get_app_config
    from ...database import get_session_factory

    global _incident_manager
    if _incident_manager is None:
        config = get_app_config()
        factory = get_session_factory(config)
        _incident_manager = IncidentManager(db_session_factory=factory)
    return _incident_manager


# --- Request bodies ---

class CreateIncidentRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    severity: str = Field(pattern=r"^(critical|high|medium|low)$")
    category: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=5000)
    source_alert_ids: Optional[list[int]] = None


class UpdateStatusRequest(BaseModel):
    new_status: str = Field(pattern=r"^(open|investigating|contained|resolved|closed)$")
    note: Optional[str] = Field(default=None, max_length=5000)


class AssignRequest(BaseModel):
    username: str


class AddNoteRequest(BaseModel):
    note: str = Field(min_length=1, max_length=5000)


class AddTimelineEventRequest(BaseModel):
    event: str
    details: Optional[str] = None


class LinkAlertsRequest(BaseModel):
    alert_ids: list[int]


# --- Endpoints ---

@router.get("/")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List incidents with optional filters."""
    manager = _get_incident_manager()
    incidents = await manager.list_incidents(
        status=status,
        severity=severity,
        assigned_to=assigned_to,
        limit=limit,
        offset=offset,
    )
    return incidents


@router.post("/", status_code=201)
async def create_incident(
    body: CreateIncidentRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_INCIDENTS)),
):
    """Create a new incident."""
    manager = _get_incident_manager()
    result = await manager.create_incident(
        title=body.title,
        severity=body.severity,
        source_alert_ids=body.source_alert_ids,
        category=body.category,
        description=body.description,
        created_by=current_user.get("sub", "unknown"),
    )
    return result


@router.get("/stats")
async def get_incident_stats(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get incident statistics (counts by status and severity)."""
    manager = _get_incident_manager()
    stats = await manager.get_stats()
    return stats


@router.get("/{incident_id}")
async def get_incident(
    incident_id: int,
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a single incident by ID."""
    manager = _get_incident_manager()
    incident = await manager.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/{incident_id}/status")
async def update_incident_status(
    incident_id: int,
    body: UpdateStatusRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_INCIDENTS)),
):
    """Update the status of an incident with transition validation."""
    manager = _get_incident_manager()
    result = await manager.update_status(
        incident_id=incident_id,
        new_status=body.new_status,
        actor=current_user.get("sub", "unknown"),
        note=body.note,
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.patch("/{incident_id}/assign")
async def assign_incident(
    incident_id: int,
    body: AssignRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_INCIDENTS)),
):
    """Assign an incident to a user."""
    manager = _get_incident_manager()
    result = await manager.assign_incident(
        incident_id=incident_id,
        username=body.username,
        actor=current_user.get("sub", "unknown"),
    )
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/{incident_id}/note")
async def add_incident_note(
    incident_id: int,
    body: AddNoteRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_INCIDENTS)),
):
    """Add a note to an incident."""
    manager = _get_incident_manager()
    result = await manager.add_note(
        incident_id=incident_id,
        note=body.note,
        actor=current_user.get("sub", "unknown"),
    )
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/{incident_id}/timeline")
async def add_timeline_event(
    incident_id: int,
    body: AddTimelineEventRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_INCIDENTS)),
):
    """Add a custom timeline event to an incident."""
    manager = _get_incident_manager()
    result = await manager.add_timeline_event(
        incident_id=incident_id,
        event=body.event,
        actor=current_user.get("sub", "unknown"),
        details=body.details,
    )
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/{incident_id}/actions")
async def get_incident_actions(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get all remediation actions linked to an incident."""
    # Verify the incident exists
    inc_result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = inc_result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Query remediation actions for this incident
    result = await db.execute(
        select(RemediationAction)
        .where(RemediationAction.incident_id == incident_id)
        .order_by(desc(RemediationAction.created_at))
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
            "rollback_data": json.loads(r.rollback_data_json) if r.rollback_data_json else {},
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("/{incident_id}/link-alerts")
async def link_alerts_to_incident(
    incident_id: int,
    body: LinkAlertsRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_INCIDENTS)),
):
    """Link alerts to an incident."""
    manager = _get_incident_manager()
    result = await manager.link_alerts(incident_id, body.alert_ids)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/{incident_id}/linked-alerts")
async def get_linked_alerts(
    incident_id: int,
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get all alerts linked to an incident."""
    manager = _get_incident_manager()
    alerts = await manager.get_linked_alerts(incident_id)
    return {"incident_id": incident_id, "alerts": alerts}
