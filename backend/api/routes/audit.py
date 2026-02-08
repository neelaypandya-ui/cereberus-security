"""Audit log routes."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_VIEW_AUDIT
from ...dependencies import get_db
from ...models.audit_log import AuditLog

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs")
async def get_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    username: str | None = None,
    action: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_AUDIT)),
):
    """Get audit log entries with optional filters."""
    query = select(AuditLog).order_by(AuditLog.timestamp.desc())
    if username:
        query = query.where(AuditLog.username == username)
    if action:
        query = query.where(AuditLog.action == action)
    query = query.limit(limit)

    result = await db.execute(query)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "username": r.username,
            "action": r.action,
            "endpoint": r.endpoint,
            "target": r.target,
            "details_json": r.details_json,
            "ip_address": r.ip_address,
            "status_code": r.status_code,
        }
        for r in rows
    ]


@router.get("/logs/{log_id}")
async def get_audit_log(
    log_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_AUDIT)),
):
    """Get a single audit log entry by ID."""
    result = await db.execute(select(AuditLog).where(AuditLog.id == log_id))
    row = result.scalar_one_or_none()
    if not row:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Audit log not found")
    return {
        "id": row.id,
        "timestamp": row.timestamp.isoformat(),
        "username": row.username,
        "action": row.action,
        "endpoint": row.endpoint,
        "target": row.target,
        "details_json": row.details_json,
        "ip_address": row.ip_address,
        "status_code": row.status_code,
    }
