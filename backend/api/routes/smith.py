"""Agent Smith adversary simulation routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD, PERM_MANAGE_SETTINGS
from ...bridge import validate_and_log, SmithStatusResponse, SmithSessionResult, SmithAttackEvent
from ...dependencies import get_agent_smith

router = APIRouter(prefix="/smith", tags=["smith"])


class EngageRequest(BaseModel):
    intensity: int = 1
    categories: Optional[list[str]] = None
    duration: int = 300


@router.post("/engage")
async def engage_smith(
    body: EngageRequest,
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Start an adversary simulation session."""
    smith = get_agent_smith()
    try:
        result = await smith.engage(
            intensity=body.intensity,
            categories=body.categories,
            duration=body.duration,
        )
        if result.get("status") == "rejected":
            raise HTTPException(status_code=409, detail=result.get("message", result.get("reason", "Engagement rejected")))
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/disengage")
async def disengage_smith(
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Emergency stop — kill all simulations immediately."""
    smith = get_agent_smith()
    result = await smith.disengage()
    return result


@router.get("/status")
async def get_smith_status(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get current session status."""
    smith = get_agent_smith()
    return validate_and_log(smith.get_status(), SmithStatusResponse, "GET /smith/status")


@router.get("/results")
async def get_smith_results(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get all session results."""
    smith = get_agent_smith()
    return validate_and_log(smith.get_results(), SmithSessionResult, "GET /smith/results")


@router.get("/results/{session_id}")
async def get_smith_result(
    session_id: str,
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get a specific session result."""
    smith = get_agent_smith()
    results = smith.get_results()
    for r in results:
        if r.get("session_id") == session_id:
            return validate_and_log(r, SmithSessionResult, "GET /smith/results/{id}")
    raise HTTPException(status_code=404, detail="Session not found")


@router.get("/attacks")
async def get_smith_attacks(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get current/recent attack log for live feed."""
    smith = get_agent_smith()
    return validate_and_log(smith.get_attack_log(), SmithAttackEvent, "GET /smith/attacks")


@router.get("/categories")
async def get_smith_categories(
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get available attack simulation categories."""
    smith = get_agent_smith()
    return smith.get_categories()
