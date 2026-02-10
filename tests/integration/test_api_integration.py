"""Integration tests — full API round-trips against in-memory database."""

import pytest


pytestmark = pytest.mark.asyncio(loop_scope="session")


# -----------------------------------------------------------------------
# 1. Login returns token
# -----------------------------------------------------------------------

async def test_login_returns_token(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


# -----------------------------------------------------------------------
# 2. Protected endpoint rejects unauthenticated
# -----------------------------------------------------------------------

async def test_protected_rejects_unauthenticated(client):
    resp = await client.get("/api/v1/alerts/")
    assert resp.status_code in (401, 403)


# -----------------------------------------------------------------------
# 3. Protected endpoint accepts valid auth
# -----------------------------------------------------------------------

async def test_protected_accepts_valid_auth(client, admin_headers):
    resp = await client.get("/api/v1/alerts/", headers=admin_headers)
    assert resp.status_code == 200


# -----------------------------------------------------------------------
# 4. Health endpoint returns 200
# -----------------------------------------------------------------------

async def test_root_endpoint(client):
    # The root endpoint serves the SPA or returns app info
    resp = await client.get("/")
    assert resp.status_code == 200


# -----------------------------------------------------------------------
# 5. Alert list works (empty on fresh DB)
# -----------------------------------------------------------------------

async def test_alert_list_empty(client, admin_headers):
    resp = await client.get("/api/v1/alerts/", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


# -----------------------------------------------------------------------
# 6. AI status returns detectors/ensemble/baseline
# -----------------------------------------------------------------------

async def test_ai_status(client, admin_headers):
    resp = await client.get("/api/v1/ai/status", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "detectors" in data
    assert "ensemble" in data
    assert "baseline" in data


# -----------------------------------------------------------------------
# 7. Backup list works
# -----------------------------------------------------------------------

async def test_backup_list(client, admin_headers):
    resp = await client.get("/api/v1/maintenance/backups", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "backups" in data


# -----------------------------------------------------------------------
# 8. Sword dry-run toggle works
# -----------------------------------------------------------------------

async def test_sword_dry_run_toggle(client, admin_headers):
    # Get initial dry-run status
    resp = await client.get("/api/v1/bond/sword/dry-run", headers=admin_headers)
    assert resp.status_code == 200

    # Enable dry-run
    resp = await client.post(
        "/api/v1/bond/sword/dry-run?enabled=true",
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["dry_run"] is True

    # Disable dry-run
    resp = await client.post(
        "/api/v1/bond/sword/dry-run?enabled=false",
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["dry_run"] is False

    # Verify via GET
    resp = await client.get("/api/v1/bond/sword/dry-run", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["dry_run"] is False


# -----------------------------------------------------------------------
# 9. Invalid credentials rejected
# -----------------------------------------------------------------------

async def test_login_invalid_credentials(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong"},
    )
    assert resp.status_code == 401


# -----------------------------------------------------------------------
# 10. Sword stats endpoint works
# -----------------------------------------------------------------------

async def test_sword_stats(client, admin_headers):
    resp = await client.get("/api/v1/bond/sword/stats", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "enabled" in data
    assert "dry_run" in data
