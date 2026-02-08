"""Alert management routes."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_MANAGE_ALERTS, PERM_VIEW_DASHBOARD
from ...dependencies import get_db, get_incident_manager
from ...models.alert import Alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/")
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    severity: str | None = None,
    unacknowledged_only: bool = False,
    show_dismissed: bool = False,
    show_snoozed: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get alerts with optional filtering. Dismissed and snoozed alerts hidden by default."""
    query = select(Alert).order_by(Alert.timestamp.desc()).limit(limit)

    if severity:
        query = query.where(Alert.severity == severity)
    if unacknowledged_only:
        query = query.where(Alert.acknowledged == False)
    if not show_dismissed:
        query = query.where(Alert.dismissed == False)
    if not show_snoozed:
        now = datetime.now(timezone.utc)
        query = query.where(
            (Alert.snoozed_until == None) | (Alert.snoozed_until <= now)
        )

    result = await db.execute(query)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "severity": r.severity,
            "module_source": r.module_source,
            "title": r.title,
            "description": r.description,
            "vpn_status_at_event": r.vpn_status_at_event,
            "acknowledged": r.acknowledged,
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
            "dismissed": r.dismissed,
            "snoozed_until": r.snoozed_until.isoformat() if r.snoozed_until else None,
            "escalated_to_incident_id": r.escalated_to_incident_id,
        }
        for r in rows
    ]


class AcknowledgeRequest(BaseModel):
    alert_ids: list[int]


@router.post("/acknowledge")
async def acknowledge_alerts(
    body: AcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_ALERTS)),
):
    """Acknowledge one or more alerts."""
    await db.execute(
        update(Alert)
        .where(Alert.id.in_(body.alert_ids))
        .values(acknowledged=True)
    )
    await db.commit()
    return {"acknowledged": body.alert_ids}


@router.get("/{alert_id}")
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a specific alert by ID."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "id": alert.id,
        "timestamp": alert.timestamp.isoformat(),
        "severity": alert.severity,
        "module_source": alert.module_source,
        "title": alert.title,
        "description": alert.description,
        "details_json": alert.details_json,
        "vpn_status_at_event": alert.vpn_status_at_event,
        "interface_name": alert.interface_name,
        "acknowledged": alert.acknowledged,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        "feedback": alert.feedback,
        "feedback_at": alert.feedback_at.isoformat() if alert.feedback_at else None,
        "feedback_by": alert.feedback_by,
    }


class FeedbackRequest(BaseModel):
    feedback: str  # "true_positive" or "false_positive"


@router.patch("/{alert_id}/feedback")
async def submit_alert_feedback(
    alert_id: int,
    body: FeedbackRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_ALERTS)),
):
    """Submit feedback (true_positive/false_positive) for an alert."""
    if body.feedback not in ("true_positive", "false_positive"):
        raise HTTPException(status_code=400, detail="feedback must be 'true_positive' or 'false_positive'")

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.feedback = body.feedback
    alert.feedback_at = datetime.now(timezone.utc)
    alert.feedback_by = current_user.get("sub", "unknown")
    await db.commit()

    return {
        "id": alert.id,
        "feedback": alert.feedback,
        "feedback_at": alert.feedback_at.isoformat(),
        "feedback_by": alert.feedback_by,
    }


# --- Phase 12: Alert Triage ---


@router.post("/{alert_id}/dismiss")
async def dismiss_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_ALERTS)),
):
    """Dismiss an alert as not actionable."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.dismissed = True
    alert.dismissed_by = current_user.get("sub", "unknown")
    alert.dismissed_at = datetime.now(timezone.utc)
    await db.commit()

    return {"id": alert.id, "dismissed": True, "dismissed_by": alert.dismissed_by}


@router.post("/{alert_id}/escalate")
async def escalate_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_ALERTS)),
):
    """Escalate an alert to an incident."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if alert.escalated_to_incident_id:
        return {"id": alert.id, "incident_id": alert.escalated_to_incident_id, "already_escalated": True}

    # Create incident via incident manager
    incident_manager = get_incident_manager()
    incident_data = {
        "title": f"Escalated: {alert.title}",
        "severity": alert.severity,
        "description": f"Escalated from alert #{alert.id}: {alert.description}",
        "category": alert.module_source,
        "source_alert_ids": [alert.id],
        "created_by": current_user.get("sub", "unknown"),
    }

    from ...models.incident import Incident
    incident = Incident(
        title=incident_data["title"],
        severity=incident_data["severity"],
        description=incident_data["description"],
        category=incident_data["category"],
        status="open",
        created_by=incident_data["created_by"],
    )
    db.add(incident)
    await db.flush()

    alert.escalated_to_incident_id = incident.id
    alert.acknowledged = True
    await db.commit()

    return {"id": alert.id, "incident_id": incident.id, "escalated": True}


@router.post("/{alert_id}/snooze")
async def snooze_alert(
    alert_id: int,
    hours: int = Query(1, ge=1, le=24),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_ALERTS)),
):
    """Snooze an alert for a specified number of hours."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.snoozed_until = datetime.now(timezone.utc) + timedelta(hours=hours)
    await db.commit()

    return {"id": alert.id, "snoozed_until": alert.snoozed_until.isoformat()}
