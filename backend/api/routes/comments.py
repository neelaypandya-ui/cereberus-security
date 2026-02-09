"""Comment routes — collaborative comments on incidents, alerts, and anomaly events."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import require_permission, PERM_ADD_COMMENTS, PERM_VIEW_DASHBOARD
from ...dependencies import get_current_user, get_db
from ...models.comment import Comment
from ...models.user import User

router = APIRouter(prefix="/comments", tags=["comments"])

VALID_TARGET_TYPES = {"incident", "alert", "anomaly_event"}


# --- Request bodies ---

class CreateCommentRequest(BaseModel):
    content: str


class UpdateCommentRequest(BaseModel):
    content: str


# --- Helpers ---

async def _get_current_user_record(current_user: dict, db: AsyncSession) -> User:
    """Resolve JWT user to a database User record."""
    username = current_user.get("sub", "")
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Current user not found in database")
    return user


def _validate_target_type(target_type: str) -> None:
    """Validate that target_type is one of the allowed values."""
    if target_type not in VALID_TARGET_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"target_type must be one of: {', '.join(sorted(VALID_TARGET_TYPES))}",
        )


# --- Endpoints ---

@router.get("/{target_type}/{target_id}")
async def get_comments(
    target_type: str,
    target_id: int,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get all comments for a specific target (incident, alert, or anomaly_event)."""
    _validate_target_type(target_type)

    result = await db.execute(
        select(Comment)
        .where(Comment.target_type == target_type, Comment.target_id == target_id)
        .order_by(Comment.created_at.asc())
        .limit(limit)
        .offset(offset)
    )
    rows = result.scalars().all()

    return [
        {
            "id": c.id,
            "target_type": c.target_type,
            "target_id": c.target_id,
            "user_id": c.user_id,
            "username": c.username,
            "content": c.content,
            "created_at": c.created_at.isoformat(),
            "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        }
        for c in rows
    ]


@router.post("/{target_type}/{target_id}", status_code=201)
async def add_comment(
    target_type: str,
    target_id: int,
    body: CreateCommentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_ADD_COMMENTS)),
):
    """Add a comment to a target entity."""
    _validate_target_type(target_type)

    user = await _get_current_user_record(current_user, db)

    comment = Comment(
        target_type=target_type,
        target_id=target_id,
        user_id=user.id,
        username=user.username,
        content=body.content,
    )
    db.add(comment)
    await db.commit()
    await db.refresh(comment)

    return {
        "id": comment.id,
        "target_type": comment.target_type,
        "target_id": comment.target_id,
        "user_id": comment.user_id,
        "username": comment.username,
        "content": comment.content,
        "created_at": comment.created_at.isoformat(),
    }


@router.put("/{comment_id}")
async def update_comment(
    comment_id: int,
    body: UpdateCommentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_ADD_COMMENTS)),
):
    """Update own comment."""
    user = await _get_current_user_record(current_user, db)

    result = await db.execute(select(Comment).where(Comment.id == comment_id))
    comment = result.scalar_one_or_none()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Only the author can edit their own comment
    if comment.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only edit your own comments",
        )

    comment.content = body.content
    comment.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(comment)

    return {
        "id": comment.id,
        "target_type": comment.target_type,
        "target_id": comment.target_id,
        "user_id": comment.user_id,
        "username": comment.username,
        "content": comment.content,
        "created_at": comment.created_at.isoformat(),
        "updated_at": comment.updated_at.isoformat() if comment.updated_at else None,
    }


@router.delete("/{comment_id}")
async def delete_comment(
    comment_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_ADD_COMMENTS)),
):
    """Delete own comment."""
    user = await _get_current_user_record(current_user, db)

    result = await db.execute(select(Comment).where(Comment.id == comment_id))
    comment = result.scalar_one_or_none()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Only the author can delete their own comment
    if comment.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only delete your own comments",
        )

    await db.delete(comment)
    await db.commit()

    return {"deleted": comment_id}
