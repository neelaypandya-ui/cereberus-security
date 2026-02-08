"""Module management routes."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_MANAGE_SETTINGS, PERM_VIEW_DASHBOARD
from ...dependencies import get_db
from ...models.settings import ModuleStatus

router = APIRouter(prefix="/modules", tags=["modules"])


@router.get("/")
async def get_all_modules(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get status of all security modules."""
    result = await db.execute(select(ModuleStatus))
    modules = result.scalars().all()
    return [
        {
            "id": m.id,
            "module_name": m.module_name,
            "enabled": m.enabled,
            "health_status": m.health_status,
            "last_heartbeat": m.last_heartbeat.isoformat() if m.last_heartbeat else None,
        }
        for m in modules
    ]


class ModuleToggleRequest(BaseModel):
    enabled: bool


@router.post("/{module_name}/toggle")
async def toggle_module(
    module_name: str,
    body: ModuleToggleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_SETTINGS)),
):
    """Enable or disable a module."""
    result = await db.execute(
        select(ModuleStatus).where(ModuleStatus.module_name == module_name)
    )
    module = result.scalar_one_or_none()
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")

    module.enabled = body.enabled
    await db.commit()
    return {"module_name": module_name, "enabled": body.enabled}


@router.get("/{module_name}/health")
async def get_module_health(
    module_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get health status of a specific module."""
    result = await db.execute(
        select(ModuleStatus).where(ModuleStatus.module_name == module_name)
    )
    module = result.scalar_one_or_none()
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")

    return {
        "module_name": module.module_name,
        "enabled": module.enabled,
        "health_status": module.health_status,
        "last_heartbeat": module.last_heartbeat.isoformat() if module.last_heartbeat else None,
        "config": module.config_json,
    }
