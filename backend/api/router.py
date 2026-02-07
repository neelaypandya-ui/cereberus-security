"""Master API router — includes all sub-routers."""

from fastapi import APIRouter

from .routes.alerts import router as alerts_router
from .routes.analytics import router as analytics_router
from .routes.audit import router as audit_router
from .routes.auth import router as auth_router
from .routes.dashboard import router as dashboard_router
from .routes.email import router as email_router
from .routes.integrity import router as integrity_router
from .routes.modules import router as modules_router
from .routes.network import router as network_router
from .routes.persistence import router as persistence_router
from .routes.processes import router as processes_router
from .routes.reports import router as reports_router
from .routes.resources import router as resources_router
from .routes.search import router as search_router
from .routes.security import router as security_router
from .routes.settings import router as settings_router
from .routes.threats import router as threats_router
from .routes.vulnerabilities import router as vulnerabilities_router
from .routes.vpn import router as vpn_router
from .routes.ai import router as ai_router
from .websockets.events import router as ws_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth_router)
api_router.include_router(dashboard_router)
api_router.include_router(vpn_router)
api_router.include_router(network_router)
api_router.include_router(alerts_router)
api_router.include_router(modules_router)
api_router.include_router(settings_router)
api_router.include_router(security_router)
api_router.include_router(integrity_router)
api_router.include_router(processes_router)
api_router.include_router(vulnerabilities_router)
api_router.include_router(email_router)
api_router.include_router(threats_router)
api_router.include_router(resources_router)
api_router.include_router(persistence_router)
api_router.include_router(analytics_router)
api_router.include_router(reports_router)
api_router.include_router(audit_router)
api_router.include_router(search_router)
api_router.include_router(ai_router)

# WebSocket router is mounted at root level (no prefix)
websocket_router = ws_router
