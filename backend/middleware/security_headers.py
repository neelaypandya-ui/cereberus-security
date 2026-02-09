"""The Shield Wall — security headers middleware."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class ShieldWallMiddleware(BaseHTTPMiddleware):
    """Injects security headers into every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self'"
        )

        # Cache-Control based on endpoint
        path = request.url.path
        if request.method != "GET":
            response.headers["Cache-Control"] = "no-store"
        elif "/health" in path or "/dashboard/summary" in path:
            response.headers["Cache-Control"] = "private, max-age=10"
        elif "/analytics/" in path:
            response.headers["Cache-Control"] = "private, max-age=30"
        elif path.startswith("/api/v1/"):
            response.headers["Cache-Control"] = "private, no-cache"

        return response
