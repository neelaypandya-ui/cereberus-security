"""Application settings routes."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...dependencies import get_current_user, get_db
from ...models.settings import Settings

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/")
async def get_all_settings(
    category: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get all settings, optionally filtered by category."""
    query = select(Settings)
    if category:
        query = query.where(Settings.category == category)

    result = await db.execute(query)
    rows = result.scalars().all()
    return [
        {
            "id": s.id,
            "key": s.key,
            "value": s.value,
            "category": s.category,
            "updated_at": s.updated_at.isoformat(),
        }
        for s in rows
    ]


class SettingUpdateRequest(BaseModel):
    value: str


@router.put("/{key}")
async def update_setting(
    key: str,
    body: SettingUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update a setting value."""
    result = await db.execute(select(Settings).where(Settings.key == key))
    setting = result.scalar_one_or_none()

    if setting:
        setting.value = body.value
    else:
        setting = Settings(key=key, value=body.value)
        db.add(setting)

    await db.commit()
    return {"key": key, "value": body.value}
