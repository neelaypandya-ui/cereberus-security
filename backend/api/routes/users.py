"""User management routes — CRUD, role assignment, and API key management."""

import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.rbac import (
    DEFAULT_ROLES,
    require_permission,
    PERM_MANAGE_USERS,
    PERM_VIEW_DASHBOARD,
)
from ...dependencies import get_current_user, get_db
from ...models.api_key import APIKey
from ...models.role import Role
from ...models.user import User
from ...models.user_role import UserRole
from ...utils.security import hash_password, validate_password_strength

router = APIRouter(prefix="/users", tags=["users"])


# --- Request / Response bodies ---

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None


class AssignRoleRequest(BaseModel):
    role_id: int


class CreateAPIKeyRequest(BaseModel):
    name: str
    permissions: Optional[list[str]] = None
    expires_at: Optional[str] = None  # ISO datetime string


# --- Helper ---

async def _get_user_or_404(user_id: int, db: AsyncSession) -> User:
    """Fetch user by ID or raise 404."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def _get_current_user_id(current_user: dict, db: AsyncSession) -> int:
    """Resolve the current JWT user to a database user ID."""
    username = current_user.get("sub", "")
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Current user not found in database")
    return user.id


# --- User CRUD ---

@router.get("/")
async def list_users(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_USERS)),
):
    """List all users (admin only)."""
    result = await db.execute(
        select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    )
    rows = result.scalars().all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "created_at": u.created_at.isoformat(),
            "last_login": u.last_login.isoformat() if u.last_login else None,
        }
        for u in rows
    ]


@router.post("/", status_code=201)
async def create_user(
    body: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_USERS)),
):
    """Create a new user (admin only)."""
    # Check for existing username
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    try:
        validate_password_strength(body.password)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "created_at": user.created_at.isoformat(),
    }


# --- Roles listing (must be defined before /{user_id} to avoid path conflict) ---

@router.get("/roles")
async def list_roles(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List all available roles with their permissions."""
    result = await db.execute(select(Role).order_by(Role.name))
    db_roles = result.scalars().all()

    roles = []
    for role in db_roles:
        roles.append({
            "id": role.id,
            "name": role.name,
            "description": role.description,
            "permissions": json.loads(role.permissions_json) if role.permissions_json else [],
            "created_at": role.created_at.isoformat(),
        })

    # If no DB roles exist yet, return the default role definitions
    if not roles:
        for name, defn in DEFAULT_ROLES.items():
            roles.append({
                "id": None,
                "name": name,
                "description": defn["description"],
                "permissions": defn["permissions"],
                "created_at": None,
            })

    return roles


# --- API Keys (must be defined before /{user_id} to avoid path conflict) ---

@router.post("/api-keys", status_code=201)
async def create_api_key(
    body: CreateAPIKeyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Generate a new API key for the current user. Returns the raw key ONCE."""
    user_id = await _get_current_user_id(current_user, db)

    raw_key = secrets.token_hex(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:8]

    expires_at = None
    if body.expires_at:
        try:
            expires_at = datetime.fromisoformat(body.expires_at)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid expires_at format. Use ISO 8601.",
            )

    api_key = APIKey(
        user_id=user_id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        name=body.name,
        permissions_json=json.dumps(body.permissions) if body.permissions else None,
        expires_at=expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return {
        "id": api_key.id,
        "key": raw_key,  # Only returned ONCE
        "key_prefix": key_prefix,
        "name": api_key.name,
        "created_at": api_key.created_at.isoformat(),
        "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
    }


@router.get("/api-keys")
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """List current user's API keys (without the actual key values)."""
    user_id = await _get_current_user_id(current_user, db)

    result = await db.execute(
        select(APIKey)
        .where(APIKey.user_id == user_id)
        .order_by(APIKey.created_at.desc())
    )
    rows = result.scalars().all()

    return [
        {
            "id": k.id,
            "key_prefix": k.key_prefix,
            "name": k.name,
            "created_at": k.created_at.isoformat(),
            "last_used": k.last_used.isoformat() if k.last_used else None,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "revoked": k.revoked,
        }
        for k in rows
    ]


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Revoke an API key belonging to the current user."""
    user_id = await _get_current_user_id(current_user, db)

    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user_id)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.revoked = True
    await db.commit()

    return {"id": key_id, "status": "revoked"}


# --- User by ID ---

@router.get("/{user_id}")
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get user detail."""
    user = await _get_user_or_404(user_id, db)
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "created_at": user.created_at.isoformat(),
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }


@router.put("/{user_id}")
async def update_user(
    user_id: int,
    body: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_USERS)),
):
    """Update a user (admin only)."""
    user = await _get_user_or_404(user_id, db)

    if body.username is not None:
        # Check uniqueness
        existing = await db.execute(
            select(User).where(User.username == body.username, User.id != user_id)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists",
            )
        user.username = body.username

    if body.role is not None:
        user.role = body.role

    if body.password is not None:
        try:
            validate_password_strength(body.password)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
        user.password_hash = hash_password(body.password)

    await db.commit()
    await db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "created_at": user.created_at.isoformat(),
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_USERS)),
):
    """Delete a user (admin only, cannot delete self)."""
    user = await _get_user_or_404(user_id, db)

    # Prevent self-deletion
    current_username = current_user.get("sub", "")
    if user.username == current_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    await db.delete(user)
    await db.commit()
    return {"deleted": user_id}


# --- Role Assignment ---

@router.post("/{user_id}/roles")
async def assign_role(
    user_id: int,
    body: AssignRoleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_USERS)),
):
    """Assign a role to a user (admin only)."""
    # Verify user exists
    await _get_user_or_404(user_id, db)

    # Verify role exists
    role_result = await db.execute(select(Role).where(Role.id == body.role_id))
    if not role_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Role not found")

    # Check for duplicate assignment
    existing = await db.execute(
        select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == body.role_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role already assigned to user",
        )

    user_role = UserRole(user_id=user_id, role_id=body.role_id)
    db.add(user_role)
    await db.commit()

    return {"user_id": user_id, "role_id": body.role_id, "status": "assigned"}


@router.delete("/{user_id}/roles/{role_id}")
async def remove_role(
    user_id: int,
    role_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_MANAGE_USERS)),
):
    """Remove a role from a user (admin only)."""
    result = await db.execute(
        select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
        )
    )
    user_role = result.scalar_one_or_none()
    if not user_role:
        raise HTTPException(status_code=404, detail="Role assignment not found")

    await db.delete(user_role)
    await db.commit()

    return {"user_id": user_id, "role_id": role_id, "status": "removed"}


@router.get("/{user_id}/roles")
async def get_user_roles(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission(PERM_VIEW_DASHBOARD)),
):
    """Get all roles assigned to a user."""
    await _get_user_or_404(user_id, db)

    result = await db.execute(
        select(UserRole.role_id).where(UserRole.user_id == user_id)
    )
    role_ids = result.scalars().all()

    roles = []
    for role_id in role_ids:
        role_result = await db.execute(select(Role).where(Role.id == role_id))
        role = role_result.scalar_one_or_none()
        if role:
            roles.append({
                "id": role.id,
                "name": role.name,
                "description": role.description,
                "permissions": json.loads(role.permissions_json) if role.permissions_json else [],
                "created_at": role.created_at.isoformat(),
            })

    return roles


