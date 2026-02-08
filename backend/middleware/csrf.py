"""CSRF protection middleware.

Validates X-CSRF-Token header on state-changing requests (POST, PUT, PATCH, DELETE).
The CSRF token is a SHA-256 hash of the JWT + secret key, issued at login.
Exempt paths: /auth/login, /auth/register (no session yet), and API key requests.
"""

import hashlib

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from ..config import get_config
from ..utils.logging import get_logger

logger = get_logger("middleware.csrf")

# Paths exempt from CSRF validation (no session context)
CSRF_EXEMPT_PATHS = {
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
    "/health",
}

# Methods that require CSRF validation
CSRF_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class CSRFMiddleware(BaseHTTPMiddleware):
    """Validates CSRF token on state-changing requests."""

    async def dispatch(self, request: Request, call_next):
        # Only validate state-changing methods
        if request.method not in CSRF_METHODS:
            return await call_next(request)

        # Skip exempt paths
        if request.url.path in CSRF_EXEMPT_PATHS:
            return await call_next(request)

        # Skip WebSocket upgrades
        if request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        # Skip if using API key auth (no CSRF needed for programmatic access)
        if request.headers.get("X-API-Key"):
            return await call_next(request)

        # Skip if no session cookie (Bearer-only clients handle their own security)
        session_cookie = request.cookies.get("cereberus_session")
        if not session_cookie:
            return await call_next(request)

        # Validate CSRF token
        csrf_token = request.headers.get("X-CSRF-Token")
        if not csrf_token:
            logger.warning("csrf_missing", path=request.url.path)
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing"},
            )

        config = get_config()
        expected = hashlib.sha256(
            f"{session_cookie}:{config.secret_key}:csrf".encode()
        ).hexdigest()

        if csrf_token != expected:
            logger.warning("csrf_invalid", path=request.url.path)
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token invalid"},
            )

        return await call_next(request)
