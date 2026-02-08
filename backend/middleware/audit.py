"""Audit middleware — logs POST/PUT/DELETE/PATCH requests to the database."""

import json
import asyncio
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..utils.logging import get_logger

logger = get_logger("middleware.audit")

# Methods to audit
AUDITED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Paths to skip auditing
SKIP_PATHS = {"/ws/events"}

# Semantic event mapping: (method, path_prefix) -> event name
SEMANTIC_EVENTS: list[tuple[str, str, str]] = [
    ("POST", "/api/v1/remediation/execute", "remediation_executed"),
    ("POST", "/api/v1/incidents", "incident_created"),
    ("PATCH", "/api/v1/incidents", "incident_updated"),
    ("POST", "/api/v1/playbooks", "playbook_created"),
    ("DELETE", "/api/v1/playbooks", "playbook_deleted"),
    ("POST", "/api/v1/users", "user_created"),
    ("DELETE", "/api/v1/users", "user_deleted"),
    ("POST", "/api/v1/feeds", "feed_created"),
    ("POST", "/api/v1/ioc", "ioc_created"),
    ("POST", "/api/v1/maintenance/backup", "backup_triggered"),
    ("POST", "/api/v1/maintenance/cleanup", "cleanup_triggered"),
    ("POST", "/api/v1/auth/login", "login_attempt"),
]


def _resolve_semantic_event(method: str, path: str) -> str | None:
    """Resolve a semantic event name from the request method and path."""
    for evt_method, evt_prefix, evt_name in SEMANTIC_EVENTS:
        if method == evt_method and path.startswith(evt_prefix):
            return evt_name
    return None


class AuditMiddleware(BaseHTTPMiddleware):
    """Intercepts mutating requests and records them to the audit_logs table."""

    def __init__(self, app, session_factory=None):
        super().__init__(app)
        self._session_factory = session_factory

    def _get_session_factory(self):
        if self._session_factory is None:
            try:
                from ..config import get_config
                from ..database import get_session_factory
                self._session_factory = get_session_factory(get_config())
            except Exception:
                pass
        return self._session_factory

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method not in AUDITED_METHODS:
            return await call_next(request)

        path = request.url.path
        if path in SKIP_PATHS:
            return await call_next(request)

        response = await call_next(request)

        # Fire-and-forget audit log
        try:
            username = self._extract_username(request)
            ip_address = request.client.host if request.client else None
            semantic_event = _resolve_semantic_event(request.method, path)

            asyncio.create_task(self._record_audit(
                username=username,
                action=request.method,
                endpoint=path,
                target=request.url.query or None,
                ip_address=ip_address,
                status_code=response.status_code,
                semantic_event=semantic_event,
            ))
        except Exception as e:
            logger.error("audit_dispatch_error", error=str(e))

        return response

    def _extract_username(self, request: Request) -> str | None:
        """Extract username from JWT in Authorization header."""
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:]
        try:
            from ..utils.security import decode_access_token
            from ..config import get_config
            config = get_config()
            payload = decode_access_token(token, config.secret_key, config.jwt_algorithm)
            if payload:
                return payload.get("sub")
        except Exception:
            pass
        return None

    async def _record_audit(self, username, action, endpoint, target, ip_address, status_code, semantic_event=None):
        """Write audit record to database."""
        factory = self._get_session_factory()
        if factory is None:
            return
        try:
            from ..models.audit_log import AuditLog
            async with factory() as session:
                log = AuditLog(
                    timestamp=datetime.now(timezone.utc),
                    username=username,
                    action=action,
                    endpoint=endpoint,
                    target=target,
                    ip_address=ip_address,
                    status_code=status_code,
                    semantic_event=semantic_event,
                )
                session.add(log)
                await session.commit()
        except Exception as e:
            logger.error("audit_record_failed", error=str(e))
