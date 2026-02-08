"""Notification channel routes — multi-channel notification config + testing."""

import json

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...dependencies import get_db, get_app_config
from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_MANAGE_NOTIFICATIONS
from ...models.notification_channel import NotificationChannel


router = APIRouter(prefix="/notifications", tags=["notifications"])


# ---------------------------------------------------------------------------
# Lazy singleton for NotificationDispatcher
# ---------------------------------------------------------------------------
_notification_dispatcher = None


def _get_notification_dispatcher():
    global _notification_dispatcher
    if _notification_dispatcher is None:
        from ...intel.notification_dispatcher import NotificationDispatcher
        from ...database import get_session_factory
        config = get_app_config()
        factory = get_session_factory(config)
        _notification_dispatcher = NotificationDispatcher(
            db_session_factory=factory, config=config
        )
    return _notification_dispatcher


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class ChannelCreate(BaseModel):
    name: str
    channel_type: str  # webhook, smtp, desktop
    config: dict | None = None
    enabled: bool = True
    events: list[str] | None = None


class ChannelUpdate(BaseModel):
    name: str | None = None
    channel_type: str | None = None
    config: dict | None = None
    enabled: bool | None = None
    events: list[str] | None = None


# ---------------------------------------------------------------------------
# Supported event types (static)
# ---------------------------------------------------------------------------
SUPPORTED_EVENT_TYPES = [
    "alert.critical",
    "alert.high",
    "alert.medium",
    "alert.low",
    "anomaly.detected",
    "anomaly.ensemble",
    "incident.created",
    "incident.escalated",
    "incident.resolved",
    "vpn.disconnected",
    "vpn.leak_detected",
    "brute_force.blocked",
    "file_integrity.changed",
    "vulnerability.found",
    "threat_feed.new_ioc",
    "resource.threshold",
    "persistence.detected",
    "export.completed",
    "system.module_down",
    "system.training_complete",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _channel_to_dict(ch: NotificationChannel) -> dict:
    return {
        "id": ch.id,
        "name": ch.name,
        "channel_type": ch.channel_type,
        "config": json.loads(ch.config_json) if ch.config_json else {},
        "enabled": ch.enabled,
        "events": json.loads(ch.events_json) if ch.events_json else [],
        "created_at": ch.created_at.isoformat() if ch.created_at else None,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/channels")
async def list_channels(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all notification channels."""
    result = await db.execute(
        select(NotificationChannel).order_by(NotificationChannel.created_at.desc())
    )
    rows = result.scalars().all()
    return [_channel_to_dict(ch) for ch in rows]


@router.post("/channels", status_code=status.HTTP_201_CREATED)
async def create_channel(
    body: ChannelCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_NOTIFICATIONS)),
):
    """Create a new notification channel."""
    # Validate channel_type
    valid_types = ("webhook", "smtp", "desktop")
    if body.channel_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"channel_type must be one of {valid_types}",
        )

    # Validate events if provided
    if body.events:
        invalid_events = [e for e in body.events if e not in SUPPORTED_EVENT_TYPES]
        if invalid_events:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported event types: {invalid_events}",
            )

    channel = NotificationChannel(
        name=body.name,
        channel_type=body.channel_type,
        config_json=json.dumps(body.config) if body.config else None,
        enabled=body.enabled,
        events_json=json.dumps(body.events) if body.events else None,
    )
    db.add(channel)
    try:
        await db.commit()
        await db.refresh(channel)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Channel with name '{body.name}' already exists",
        )
    return _channel_to_dict(channel)


@router.get("/channels/{channel_id}")
async def get_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a single notification channel by ID."""
    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    return _channel_to_dict(channel)


@router.put("/channels/{channel_id}")
async def update_channel(
    channel_id: int,
    body: ChannelUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_NOTIFICATIONS)),
):
    """Update an existing notification channel."""
    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found")

    if body.name is not None:
        channel.name = body.name
    if body.channel_type is not None:
        valid_types = ("webhook", "smtp", "desktop")
        if body.channel_type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"channel_type must be one of {valid_types}",
            )
        channel.channel_type = body.channel_type
    if body.config is not None:
        channel.config_json = json.dumps(body.config)
    if body.enabled is not None:
        channel.enabled = body.enabled
    if body.events is not None:
        invalid_events = [e for e in body.events if e not in SUPPORTED_EVENT_TYPES]
        if invalid_events:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported event types: {invalid_events}",
            )
        channel.events_json = json.dumps(body.events)

    await db.commit()
    await db.refresh(channel)
    return _channel_to_dict(channel)


@router.delete("/channels/{channel_id}")
async def delete_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_NOTIFICATIONS)),
):
    """Delete a notification channel."""
    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found")

    await db.delete(channel)
    await db.commit()
    return {"deleted": channel_id}


@router.post("/channels/{channel_id}/test")
async def test_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_NOTIFICATIONS)),
):
    """Send a test notification through a channel."""
    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found")

    if not channel.enabled:
        raise HTTPException(status_code=400, detail="Channel is disabled — enable it before testing")

    dispatcher = _get_notification_dispatcher()
    try:
        test_result = await dispatcher.send_test(
            channel_id=channel_id,
            channel_type=channel.channel_type,
            config=json.loads(channel.config_json) if channel.config_json else {},
        )
    except Exception as e:
        return {
            "channel_id": channel_id,
            "success": False,
            "error": str(e),
        }

    return {
        "channel_id": channel_id,
        "channel_type": channel.channel_type,
        "success": test_result.get("success", False),
        "message": test_result.get("message", "Test notification sent"),
    }


@router.get("/event-types")
async def list_event_types(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all supported notification event types."""
    return {
        "event_types": SUPPORTED_EVENT_TYPES,
        "total": len(SUPPORTED_EVENT_TYPES),
    }
