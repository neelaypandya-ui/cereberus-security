"""IOC (Indicators of Compromise) routes — CRUD, search, bulk import, matching."""

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...dependencies import get_db, get_app_config
from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_MANAGE_FEEDS
from ...bridge import validate_and_log, IOCResponse
from ...models.ioc import IOC


router = APIRouter(prefix="/ioc", tags=["ioc"])


# ---------------------------------------------------------------------------
# Lazy singleton for IOCMatcher
# ---------------------------------------------------------------------------
_ioc_matcher = None


def _get_ioc_matcher():
    global _ioc_matcher
    if _ioc_matcher is None:
        from ...intel.ioc_matcher import IOCMatcher
        from ...database import get_session_factory
        config = get_app_config()
        factory = get_session_factory(config)
        _ioc_matcher = IOCMatcher(db_session_factory=factory)
    return _ioc_matcher


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class IOCCreate(BaseModel):
    ioc_type: str  # ip, domain, url, hash, email
    value: str
    source: str | None = None
    severity: str = "medium"
    tags: list[str] | None = None
    context: dict | None = None


class IOCBulkImport(BaseModel):
    items: list[IOCCreate]


class IOCCheckRequest(BaseModel):
    values: list[str]
    ioc_type: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ioc_to_dict(ioc: IOC) -> dict:
    _expires_at = getattr(ioc, "expires_at", None)
    _fp_at = getattr(ioc, "false_positive_at", None)
    _last_hit = getattr(ioc, "last_hit_at", None)
    return {
        "id": ioc.id,
        "ioc_type": ioc.ioc_type,
        "value": ioc.value,
        "source": ioc.source,
        "severity": ioc.severity,
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
        "tags": json.loads(ioc.tags_json) if ioc.tags_json else [],
        "context": json.loads(ioc.context_json) if ioc.context_json else {},
        "active": ioc.active,
        "feed_id": ioc.feed_id,
        "confidence": getattr(ioc, "confidence", None),
        "expires_at": _expires_at.isoformat() if _expires_at else None,
        "false_positive": getattr(ioc, "false_positive", False),
        "false_positive_reason": getattr(ioc, "false_positive_reason", None),
        "false_positive_by": getattr(ioc, "false_positive_by", None),
        "false_positive_at": _fp_at.isoformat() if _fp_at else None,
        "hit_count": getattr(ioc, "hit_count", 0),
        "last_hit_at": _last_hit.isoformat() if _last_hit else None,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/")
async def list_iocs(
    ioc_type: str | None = None,
    active: bool | None = None,
    source: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List IOCs with optional filtering."""
    query = select(IOC).order_by(IOC.first_seen.desc()).limit(limit).offset(offset)

    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if active is not None:
        query = query.where(IOC.active == active)
    if source:
        query = query.where(IOC.source == source)

    result = await db.execute(query)
    rows = result.scalars().all()
    return validate_and_log([_ioc_to_dict(r) for r in rows], IOCResponse, "GET /ioc/")


@router.get("/search")
async def search_iocs(
    q: str = Query(..., min_length=1, max_length=512),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Search IOCs by value pattern."""
    result = await db.execute(
        select(IOC)
        .where(IOC.value.ilike(f"%{q}%"))
        .order_by(IOC.first_seen.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return validate_and_log([_ioc_to_dict(r) for r in rows], IOCResponse, "GET /ioc/search")


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_ioc(
    body: IOCCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Add a single IOC."""
    ioc = IOC(
        ioc_type=body.ioc_type,
        value=body.value,
        source=body.source,
        severity=body.severity,
        tags_json=json.dumps(body.tags) if body.tags else None,
        context_json=json.dumps(body.context) if body.context else None,
        active=True,
    )
    db.add(ioc)
    try:
        await db.commit()
        await db.refresh(ioc)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"IOC with type '{body.ioc_type}' and value '{body.value}' already exists",
        )
    return _ioc_to_dict(ioc)


@router.post("/bulk", status_code=status.HTTP_201_CREATED)
async def bulk_import_iocs(
    body: IOCBulkImport,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Bulk import IOCs. Skips duplicates."""
    created = 0
    skipped = 0
    errors = []

    for item in body.items:
        # Check for existing IOC with same type+value
        existing = await db.execute(
            select(IOC).where(IOC.ioc_type == item.ioc_type, IOC.value == item.value)
        )
        if existing.scalar_one_or_none():
            skipped += 1
            continue

        ioc = IOC(
            ioc_type=item.ioc_type,
            value=item.value,
            source=item.source,
            severity=item.severity,
            tags_json=json.dumps(item.tags) if item.tags else None,
            context_json=json.dumps(item.context) if item.context else None,
            active=True,
        )
        db.add(ioc)
        created += 1

    try:
        await db.commit()
    except Exception as e:
        await db.rollback()
        errors.append(str(e))

    return {
        "created": created,
        "skipped": skipped,
        "errors": errors,
        "total_submitted": len(body.items),
    }


@router.post("/check")
async def check_iocs(
    body: IOCCheckRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Check a list of values against the IOC database."""
    matcher = _get_ioc_matcher()
    try:
        matches = await matcher.check(
            values=body.values,
            ioc_type=body.ioc_type,
        )
        return {"matches": matches, "checked": len(body.values)}
    except Exception:
        # Fallback: direct DB lookup if matcher is unavailable
        query = select(IOC).where(IOC.value.in_(body.values), IOC.active == True)
        if body.ioc_type:
            query = query.where(IOC.ioc_type == body.ioc_type)
        result = await db.execute(query)
        rows = result.scalars().all()
        return {
            "matches": [_ioc_to_dict(r) for r in rows],
            "checked": len(body.values),
        }


@router.get("/stats")
async def ioc_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """IOC statistics — counts by type, source, and severity."""
    # Count by type
    type_result = await db.execute(
        select(IOC.ioc_type, func.count(IOC.id))
        .where(IOC.active == True)
        .group_by(IOC.ioc_type)
    )
    by_type = [{"ioc_type": row[0], "count": row[1]} for row in type_result.all()]

    # Count by source
    source_result = await db.execute(
        select(IOC.source, func.count(IOC.id))
        .where(IOC.active == True)
        .group_by(IOC.source)
    )
    by_source = [{"source": row[0], "count": row[1]} for row in source_result.all()]

    # Count by severity
    severity_result = await db.execute(
        select(IOC.severity, func.count(IOC.id))
        .where(IOC.active == True)
        .group_by(IOC.severity)
    )
    by_severity = [{"severity": row[0], "count": row[1]} for row in severity_result.all()]

    # Total counts
    total_result = await db.execute(
        select(func.count(IOC.id)).where(IOC.active == True)
    )
    total_active = total_result.scalar() or 0

    inactive_result = await db.execute(
        select(func.count(IOC.id)).where(IOC.active == False)
    )
    total_inactive = inactive_result.scalar() or 0

    return {
        "total_active": total_active,
        "total_inactive": total_inactive,
        "by_type": by_type,
        "by_source": by_source,
        "by_severity": by_severity,
    }


# --- Phase 13: IOC Lifecycle Endpoints (static paths before {ioc_id}) ---

class FalsePositiveRequest(BaseModel):
    reason: str | None = None


class BulkDeactivateRequest(BaseModel):
    source: str | None = None
    ioc_type: str | None = None
    older_than_days: int | None = None


class ConfidenceUpdate(BaseModel):
    confidence: int


@router.get("/expiring")
async def get_expiring_iocs(
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get IOCs expiring within N days."""
    cutoff = datetime.now(timezone.utc) + timedelta(days=days)
    result = await db.execute(
        select(IOC)
        .where(IOC.expires_at != None, IOC.expires_at <= cutoff, IOC.active == True)
        .order_by(IOC.expires_at.asc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return validate_and_log([_ioc_to_dict(r) for r in rows], IOCResponse, "GET /ioc/expiring")


@router.post("/bulk-deactivate")
async def bulk_deactivate(
    body: BulkDeactivateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Bulk deactivate IOCs by source, type, or age."""
    from sqlalchemy import update

    query = update(IOC).where(IOC.active == True)

    if body.source:
        query = query.where(IOC.source == body.source)
    if body.ioc_type:
        query = query.where(IOC.ioc_type == body.ioc_type)
    if body.older_than_days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=body.older_than_days)
        query = query.where(IOC.first_seen < cutoff)

    result = await db.execute(query.values(active=False))
    await db.commit()

    return {"deactivated_count": result.rowcount}


@router.get("/{ioc_id}")
async def get_ioc(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a single IOC by ID."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return validate_and_log(_ioc_to_dict(ioc), IOCResponse, "GET /ioc/{id}")


@router.delete("/{ioc_id}")
async def deactivate_ioc(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Deactivate an IOC (soft delete — sets active=False)."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    ioc.active = False
    ioc.last_seen = datetime.now(timezone.utc)
    await db.commit()

    return {"deactivated": ioc_id, "active": False}


@router.post("/{ioc_id}/false-positive")
async def mark_false_positive(
    ioc_id: int,
    body: FalsePositiveRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Mark an IOC as a false positive."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    ioc.false_positive = True
    ioc.false_positive_reason = body.reason
    ioc.false_positive_by = current_user.get("sub", "unknown")
    ioc.false_positive_at = datetime.now(timezone.utc)
    await db.commit()

    return {"id": ioc_id, "false_positive": True}


@router.delete("/{ioc_id}/false-positive")
async def unmark_false_positive(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Remove false positive marking from an IOC."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    ioc.false_positive = False
    ioc.false_positive_reason = None
    ioc.false_positive_by = None
    ioc.false_positive_at = None
    await db.commit()

    return {"id": ioc_id, "false_positive": False}


@router.patch("/{ioc_id}/confidence")
async def update_confidence(
    ioc_id: int,
    body: ConfidenceUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_FEEDS)),
):
    """Manually adjust IOC confidence score."""
    if not (0 <= body.confidence <= 100):
        raise HTTPException(status_code=400, detail="Confidence must be 0-100")

    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    ioc.confidence = body.confidence
    await db.commit()

    return {"id": ioc_id, "confidence": body.confidence}
