"""The Gatekeeper — rate limiting middleware for state-changing endpoints."""

import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..utils.rate_limiter import RateLimiter
from ..utils.logging import get_logger

logger = get_logger("middleware.rate_limit")

# State-changing methods subject to rate limits
_RATE_LIMITED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Per-endpoint rate limits (requests per minute)
_ENDPOINT_LIMITS: dict[str, tuple[int, int]] = {
    "/api/v1/remediation/execute": (10, 60),
    "/api/v1/incidents": (20, 60),
    "/api/v1/playbooks": (20, 60),
    "/api/v1/ioc": (30, 60),
    "/api/v1/export": (5, 60),
    "/api/v1/auth/register": (3, 300),       # 3 per 5 min
    "/api/v1/maintenance/restore": (2, 3600), # 2 per hour
}

# Global limit for all state-changing requests: 100/min per IP
_global_limiter = RateLimiter(max_attempts=100, window_seconds=60)

# Per-endpoint limiters
_endpoint_limiters: dict[str, RateLimiter] = {}


def _get_endpoint_limiter(path: str) -> tuple[RateLimiter, str] | None:
    """Find the matching endpoint limiter for a path."""
    for prefix, (max_req, window) in _ENDPOINT_LIMITS.items():
        if path.startswith(prefix):
            if prefix not in _endpoint_limiters:
                _endpoint_limiters[prefix] = RateLimiter(max_attempts=max_req, window_seconds=window)
            return _endpoint_limiters[prefix], prefix
    return None


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class GatekeeperMiddleware(BaseHTTPMiddleware):
    """Rate limits state-changing requests per IP."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method not in _RATE_LIMITED_METHODS:
            return await call_next(request)

        client_ip = _get_client_ip(request)
        path = request.url.path

        # Check global rate limit
        if _global_limiter.is_rate_limited(client_ip):
            remaining = _global_limiter.remaining_attempts(client_ip)
            logger.warning("rate_limit_global", ip=client_ip, path=path)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"X-RateLimit-Remaining": str(remaining)},
            )
        _global_limiter.record_attempt(client_ip)

        # Check per-endpoint rate limit
        endpoint_match = _get_endpoint_limiter(path)
        if endpoint_match:
            limiter, prefix = endpoint_match
            key = f"{client_ip}:{prefix}"
            if limiter.is_rate_limited(key):
                remaining = limiter.remaining_attempts(key)
                logger.warning("rate_limit_endpoint", ip=client_ip, path=path, prefix=prefix)
                return JSONResponse(
                    status_code=429,
                    content={"detail": f"Rate limit exceeded for {prefix}. Try again later."},
                    headers={"X-RateLimit-Remaining": str(remaining)},
                )
            limiter.record_attempt(key)

        response = await call_next(request)

        # Add remaining attempts header
        remaining = _global_limiter.remaining_attempts(client_ip)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
