"""Dashboard layout routes — per-user layout customization."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_VIEW_DASHBOARD
from ...dependencies import get_db
from ...models.dashboard_layout import DashboardLayout
from ...models.user import User

router = APIRouter(prefix="/layouts", tags=["layouts"])


# --- Request bodies ---

class CreateLayoutRequest(BaseModel):
    name: str
    layout_json: str
    is_default: bool = False


class UpdateLayoutRequest(BaseModel):
    name: Optional[str] = None
    layout_json: Optional[str] = None
    is_default: Optional[bool] = None


# --- Helpers ---

async def _get_user_id(current_user: dict, db: AsyncSession) -> int:
    """Resolve JWT username to database user ID."""
    username = current_user.get("sub", "")
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Current user not found in database")
    return user.id


# --- Endpoints ---

@router.get("/")
async def list_layouts(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all layouts for the current user."""
    user_id = await _get_user_id(current_user, db)

    result = await db.execute(
        select(DashboardLayout)
        .where(DashboardLayout.user_id == user_id)
        .order_by(DashboardLayout.created_at.desc())
    )
    rows = result.scalars().all()

    return [
        {
            "id": layout.id,
            "name": layout.name,
            "layout_json": layout.layout_json,
            "is_default": layout.is_default,
            "created_at": layout.created_at.isoformat(),
        }
        for layout in rows
    ]


@router.post("/", status_code=201)
async def create_layout(
    body: CreateLayoutRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Create a new dashboard layout for the current user."""
    user_id = await _get_user_id(current_user, db)

    # If this layout is set as default, unset any existing defaults
    if body.is_default:
        await db.execute(
            update(DashboardLayout)
            .where(DashboardLayout.user_id == user_id, DashboardLayout.is_default == True)
            .values(is_default=False)
        )

    layout = DashboardLayout(
        user_id=user_id,
        name=body.name,
        layout_json=body.layout_json,
        is_default=body.is_default,
    )
    db.add(layout)
    await db.commit()
    await db.refresh(layout)

    return {
        "id": layout.id,
        "name": layout.name,
        "layout_json": layout.layout_json,
        "is_default": layout.is_default,
        "created_at": layout.created_at.isoformat(),
    }


@router.get("/default")
async def get_default_layout(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get the current user's default layout."""
    user_id = await _get_user_id(current_user, db)

    result = await db.execute(
        select(DashboardLayout).where(
            DashboardLayout.user_id == user_id,
            DashboardLayout.is_default == True,
        )
    )
    layout = result.scalar_one_or_none()

    if not layout:
        raise HTTPException(status_code=404, detail="No default layout configured")

    return {
        "id": layout.id,
        "name": layout.name,
        "layout_json": layout.layout_json,
        "is_default": layout.is_default,
        "created_at": layout.created_at.isoformat(),
    }


@router.put("/{layout_id}")
async def update_layout(
    layout_id: int,
    body: UpdateLayoutRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Update a layout belonging to the current user."""
    user_id = await _get_user_id(current_user, db)

    result = await db.execute(
        select(DashboardLayout).where(
            DashboardLayout.id == layout_id,
            DashboardLayout.user_id == user_id,
        )
    )
    layout = result.scalar_one_or_none()
    if not layout:
        raise HTTPException(status_code=404, detail="Layout not found")

    if body.name is not None:
        layout.name = body.name

    if body.layout_json is not None:
        layout.layout_json = body.layout_json

    if body.is_default is not None:
        # If setting as default, unset any other defaults
        if body.is_default:
            await db.execute(
                update(DashboardLayout)
                .where(
                    DashboardLayout.user_id == user_id,
                    DashboardLayout.is_default == True,
                    DashboardLayout.id != layout_id,
                )
                .values(is_default=False)
            )
        layout.is_default = body.is_default

    await db.commit()
    await db.refresh(layout)

    return {
        "id": layout.id,
        "name": layout.name,
        "layout_json": layout.layout_json,
        "is_default": layout.is_default,
        "created_at": layout.created_at.isoformat(),
    }


@router.delete("/{layout_id}")
async def delete_layout(
    layout_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Delete a layout belonging to the current user."""
    user_id = await _get_user_id(current_user, db)

    result = await db.execute(
        select(DashboardLayout).where(
            DashboardLayout.id == layout_id,
            DashboardLayout.user_id == user_id,
        )
    )
    layout = result.scalar_one_or_none()
    if not layout:
        raise HTTPException(status_code=404, detail="Layout not found")

    await db.delete(layout)
    await db.commit()

    return {"deleted": layout_id}
