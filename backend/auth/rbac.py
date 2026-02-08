"""Role-Based Access Control system."""

import json
from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..dependencies import get_current_user, get_db
from ..utils.logging import get_logger

logger = get_logger("auth.rbac")

# Permission constants
PERM_VIEW_DASHBOARD = "view_dashboard"
PERM_MANAGE_ALERTS = "manage_alerts"
PERM_MANAGE_INCIDENTS = "manage_incidents"
PERM_EXECUTE_REMEDIATION = "execute_remediation"
PERM_MANAGE_PLAYBOOKS = "manage_playbooks"
PERM_MANAGE_USERS = "manage_users"
PERM_MANAGE_SETTINGS = "manage_settings"
PERM_VIEW_AUDIT = "view_audit"
PERM_EXPORT_DATA = "export_data"
PERM_MANAGE_FEEDS = "manage_feeds"
PERM_MANAGE_AI = "manage_ai"
PERM_MANAGE_NOTIFICATIONS = "manage_notifications"
PERM_ADD_COMMENTS = "add_comments"

ALL_PERMISSIONS = [
    PERM_VIEW_DASHBOARD, PERM_MANAGE_ALERTS, PERM_MANAGE_INCIDENTS,
    PERM_EXECUTE_REMEDIATION, PERM_MANAGE_PLAYBOOKS, PERM_MANAGE_USERS,
    PERM_MANAGE_SETTINGS, PERM_VIEW_AUDIT, PERM_EXPORT_DATA,
    PERM_MANAGE_FEEDS, PERM_MANAGE_AI, PERM_MANAGE_NOTIFICATIONS,
    PERM_ADD_COMMENTS,
]

DEFAULT_ROLES = {
    "admin": {
        "description": "Full system access",
        "permissions": ALL_PERMISSIONS,
    },
    "analyst": {
        "description": "Security analyst — analyze, investigate, and export",
        "permissions": [
            PERM_VIEW_DASHBOARD, PERM_MANAGE_ALERTS, PERM_MANAGE_INCIDENTS,
            PERM_EXECUTE_REMEDIATION, PERM_VIEW_AUDIT, PERM_EXPORT_DATA,
            PERM_ADD_COMMENTS, PERM_MANAGE_FEEDS,
        ],
    },
    "operator": {
        "description": "Operations — monitoring and basic remediation",
        "permissions": [
            PERM_VIEW_DASHBOARD, PERM_EXECUTE_REMEDIATION, PERM_ADD_COMMENTS,
        ],
    },
    "viewer": {
        "description": "Read-only dashboard access",
        "permissions": [PERM_VIEW_DASHBOARD],
    },
}


async def get_user_permissions(user: dict, db: AsyncSession) -> list[str]:
    """Get all permissions for a user by checking their roles in the DB."""
    from ..models.user_role import UserRole
    from ..models.role import Role
    from ..models.user import User

    username = user.get("sub", "")

    # Get user ID
    result = await db.execute(select(User).where(User.username == username))
    db_user = result.scalar_one_or_none()
    if not db_user:
        return []

    # Get user's roles
    role_ids = (await db.execute(
        select(UserRole.role_id).where(UserRole.user_id == db_user.id)
    )).scalars().all()

    if not role_ids:
        # Fallback to legacy user.role field
        legacy_role = db_user.role or user.get("role", "viewer")
        role_def = DEFAULT_ROLES.get(legacy_role, DEFAULT_ROLES["viewer"])
        return role_def["permissions"]

    # Aggregate permissions from all roles
    permissions = set()
    for role_id in role_ids:
        role = (await db.execute(
            select(Role).where(Role.id == role_id)
        )).scalar_one_or_none()
        if role:
            role_perms = json.loads(role.permissions_json) if role.permissions_json else []
            permissions.update(role_perms)

    return list(permissions)


def require_permission(*required_perms: str):
    """FastAPI dependency factory that checks user has required permissions."""
    async def _check(
        current_user: dict = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> dict:
        user_perms = await get_user_permissions(current_user, db)

        for perm in required_perms:
            if perm not in user_perms:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission required: {perm}",
                )

        # Attach permissions to user dict for downstream use
        current_user["permissions"] = user_perms
        return current_user

    return _check
