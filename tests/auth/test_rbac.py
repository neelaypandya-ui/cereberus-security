"""Tests for RBAC — role-based access control permissions and enforcement."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from backend.auth.rbac import (
    ALL_PERMISSIONS,
    DEFAULT_ROLES,
    PERM_VIEW_DASHBOARD,
    get_user_permissions,
    require_permission,
)


def _make_mock_db(user=None, role_ids=None, roles=None):
    """Build a mock AsyncSession with user, role ID, and role queries.

    Args:
        user: Mock User ORM object (or None).
        role_ids: List of role IDs to return from UserRole queries.
        roles: Dict mapping role_id -> mock Role ORM object.
    """
    role_ids = role_ids or []
    roles = roles or {}

    call_counter = {"n": 0}

    async def _execute(query):
        call_counter["n"] += 1
        result = MagicMock()

        # Call 1: look up User by username
        if call_counter["n"] == 1:
            result.scalar_one_or_none = MagicMock(return_value=user)
            return result

        # Call 2: look up UserRole.role_id list
        if call_counter["n"] == 2:
            scalars = MagicMock()
            scalars.all.return_value = role_ids
            result.scalars.return_value = scalars
            return result

        # Call 3+: look up Role by ID
        role_id = role_ids[call_counter["n"] - 3] if call_counter["n"] - 3 < len(role_ids) else None
        role_obj = roles.get(role_id)
        result.scalar_one_or_none = MagicMock(return_value=role_obj)
        return result

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=_execute)
    return db


def _make_user(user_id=1, username="admin", role="admin"):
    """Create a mock User ORM object."""
    user = MagicMock()
    user.id = user_id
    user.username = username
    user.role = role
    return user


def _make_role(role_id=1, name="admin", permissions_json=None):
    """Create a mock Role ORM object."""
    import json
    role = MagicMock()
    role.id = role_id
    role.name = name
    role.permissions_json = permissions_json or json.dumps(ALL_PERMISSIONS)
    return role


class TestAdminPermissions:
    def test_admin_has_all_permissions(self):
        """The admin role should have all 13 permissions."""
        admin_perms = DEFAULT_ROLES["admin"]["permissions"]
        assert len(admin_perms) == 13
        for perm in ALL_PERMISSIONS:
            assert perm in admin_perms


class TestViewerPermissions:
    def test_viewer_has_only_view(self):
        """The viewer role should only have view_dashboard permission."""
        viewer_perms = DEFAULT_ROLES["viewer"]["permissions"]
        assert len(viewer_perms) == 1
        assert viewer_perms[0] == PERM_VIEW_DASHBOARD


class TestRequirePermissionAllows:
    @pytest.mark.asyncio
    async def test_require_permission_allows_authorized(self):
        """require_permission should allow access when user has the permission."""
        import json

        user_obj = _make_user(user_id=1, username="analyst_user", role="analyst")
        role_obj = _make_role(
            role_id=10,
            name="analyst",
            permissions_json=json.dumps([
                PERM_VIEW_DASHBOARD, "manage_alerts", "export_data",
            ]),
        )
        db = _make_mock_db(user=user_obj, role_ids=[10], roles={10: role_obj})

        current_user = {"sub": "analyst_user", "role": "analyst"}

        # Get the dependency function
        check_fn = require_permission(PERM_VIEW_DASHBOARD)

        # Call the inner check function directly
        result = await check_fn(current_user=current_user, db=db)

        assert result is not None
        assert result["sub"] == "analyst_user"
        assert PERM_VIEW_DASHBOARD in result["permissions"]


class TestRequirePermissionDenies:
    @pytest.mark.asyncio
    async def test_require_permission_denies_unauthorized(self):
        """require_permission should raise 403 when user lacks the permission."""
        import json

        user_obj = _make_user(user_id=2, username="viewer_user", role="viewer")
        role_obj = _make_role(
            role_id=20,
            name="viewer",
            permissions_json=json.dumps([PERM_VIEW_DASHBOARD]),
        )
        db = _make_mock_db(user=user_obj, role_ids=[20], roles={20: role_obj})

        current_user = {"sub": "viewer_user", "role": "viewer"}

        # Require a permission the viewer does not have
        check_fn = require_permission("manage_users")

        with pytest.raises(HTTPException) as exc_info:
            await check_fn(current_user=current_user, db=db)

        assert exc_info.value.status_code == 403
        assert "manage_users" in str(exc_info.value.detail)
