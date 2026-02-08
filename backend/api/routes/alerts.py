"""Alert management routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_MANAGE_ALERTS, PERM_VIEW_DASHBOARD
from ...dependencies import get_db
from ...models.alert import Alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/")
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    severity: str | None = None,
    unacknowledged_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get alerts with optional filtering."""
    query = select(Alert).order_by(Alert.timestamp.desc()).limit(limit)

    if severity:
        query = query.where(Alert.severity == severity)
    if unacknowledged_only:
        query = query.where(Alert.acknowledged == False)

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
