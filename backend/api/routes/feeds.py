"""Threat feed management routes — CRUD + polling for external feed sources."""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...dependencies import get_db, get_app_config
from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_MANAGE_FEEDS
from ...models.threat_feed import ThreatFeed
from ...utils.encryption import encrypt_value


router = APIRouter(prefix="/feeds", tags=["feeds"])


# ---------------------------------------------------------------------------
# Lazy singleton for FeedManager
# ---------------------------------------------------------------------------
_feed_manager = None


def _get_feed_manager():
    global _feed_manager
    if _feed_manager is None:
        from ...intel.feed_manager import FeedManager
        from ...database import get_session_factory
        config = get_app_config()
        factory = get_session_factory(config)
        _feed_manager = FeedManager(db_session_factory=factory, config=config)
    return _feed_manager


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class FeedCreate(BaseModel):
    name: str
    feed_type: str
    url: str | None = None
    api_key: str | None = None
    enabled: bool = False
    poll_interval_seconds: int = 3600
    config_json: str | None = None


class FeedUpdate(BaseModel):
    name: str | None = None
    feed_type: str | None = None
    url: str | None = None
    api_key: str | None = None
    enabled: bool | None = None
    poll_interval_seconds: int | None = None
    config_json: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _mask_api_key(encrypted_key: str | None) -> str | None:
    """Return a masked placeholder if an encrypted key exists."""
    if not encrypted_key:
        return None
    return "****encrypted****"


def _feed_to_dict(feed: ThreatFeed) -> dict:
    return {
        "id": feed.id,
        "name": feed.name,
        "feed_type": feed.feed_type,
        "url": feed.url,
        "api_key": _mask_api_key(feed.api_key_encrypted),
        "enabled": feed.enabled,
        "poll_interval_seconds": feed.poll_interval_seconds,
        "last_polled": feed.last_polled.isoformat() if feed.last_polled else None,
        "last_success": feed.last_success.isoformat() if feed.last_success else None,
        "items_count": feed.items_count,
        "config_json": json.loads(feed.config_json) if feed.config_json else None,
        "created_at": feed.created_at.isoformat() if feed.created_at else None,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/")
async def list_feeds(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all configured threat feeds."""
    result = await db.execute(
        select(ThreatFeed).order_by(ThreatFeed.created_at.desc())
    )
    rows = result.scalars().all()
    return [_feed_to_dict(f) for f in rows]


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_feed(
    body: FeedCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Create a new threat feed configuration."""
    config = get_app_config()

    # Encrypt api_key before storage
    encrypted_key = None
    if body.api_key:
        encrypted_key = encrypt_value(body.api_key, config.secret_key)

    feed = ThreatFeed(
        name=body.name,
        feed_type=body.feed_type,
        url=body.url,
        api_key_encrypted=encrypted_key,
        enabled=body.enabled,
        poll_interval_seconds=body.poll_interval_seconds,
        config_json=body.config_json,
    )
    db.add(feed)
    await db.commit()
    await db.refresh(feed)
    return _feed_to_dict(feed)


@router.get("/{feed_id}")
async def get_feed(
    feed_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a single feed by ID (api_key masked)."""
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    return _feed_to_dict(feed)


@router.put("/{feed_id}")
async def update_feed(
    feed_id: int,
    body: FeedUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Update an existing threat feed configuration."""
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    config = get_app_config()

    if body.name is not None:
        feed.name = body.name
    if body.feed_type is not None:
        feed.feed_type = body.feed_type
    if body.url is not None:
        feed.url = body.url
    if body.api_key is not None:
        feed.api_key_encrypted = encrypt_value(body.api_key, config.secret_key)
    if body.enabled is not None:
        feed.enabled = body.enabled
    if body.poll_interval_seconds is not None:
        feed.poll_interval_seconds = body.poll_interval_seconds
    if body.config_json is not None:
        feed.config_json = body.config_json

    await db.commit()
    await db.refresh(feed)
    return _feed_to_dict(feed)


@router.delete("/{feed_id}")
async def delete_feed(
    feed_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Delete a threat feed."""
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    await db.delete(feed)
    await db.commit()
    return {"deleted": feed_id}


@router.post("/{feed_id}/poll")
async def poll_feed(
    feed_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Trigger an immediate poll for a specific feed."""
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    if not feed.enabled:
        raise HTTPException(status_code=400, detail="Feed is disabled — enable it before polling")

    fm = _get_feed_manager()
    try:
        poll_result = await fm.poll_feed(feed_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Poll failed: {str(e)}")

    # Update last_polled timestamp
    feed.last_polled = datetime.now(timezone.utc)
    if poll_result.get("success"):
        feed.last_success = datetime.now(timezone.utc)
        feed.items_count = poll_result.get("items_count", feed.items_count)
    await db.commit()

    return {
        "feed_id": feed_id,
        "poll_result": poll_result,
        "last_polled": feed.last_polled.isoformat(),
    }


@router.get("/{feed_id}/status")
async def get_feed_status(
    feed_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get the current poll status for a feed."""
    result = await db.execute(select(ThreatFeed).where(ThreatFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    fm = _get_feed_manager()
    try:
        poll_status = fm.get_feed_status(feed_id)
    except Exception:
        poll_status = {"polling": False, "message": "Status unavailable"}

    return {
        "feed_id": feed_id,
        "name": feed.name,
        "enabled": feed.enabled,
        "last_polled": feed.last_polled.isoformat() if feed.last_polled else None,
        "last_success": feed.last_success.isoformat() if feed.last_success else None,
        "items_count": feed.items_count,
        "poll_status": poll_status,
    }
