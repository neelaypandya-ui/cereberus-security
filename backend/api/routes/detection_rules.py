"""Detection rules routes — rule-based threat detection queries."""

from fastapi import APIRouter, Depends, Query

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD
from ...dependencies import get_rule_engine

router = APIRouter(prefix="/detection-rules", tags=["detection-rules"])


@router.get("/")
async def list_rules(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all detection rules with their status."""
    engine = get_rule_engine()
    return engine.get_rules()


@router.get("/matches")
async def get_matches(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get recent rule matches."""
    engine = get_rule_engine()
    matches = engine.get_matches(limit=limit + offset)
    return matches[offset:offset + limit]


@router.get("/stats")
async def get_stats(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get match statistics by severity and category."""
    engine = get_rule_engine()
    return engine.get_stats()
