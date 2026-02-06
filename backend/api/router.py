"""Master API router — includes all sub-routers."""

from fastapi import APIRouter

from .routes.alerts import router as alerts_router
from .routes.auth import router as auth_router
from .routes.dashboard import router as dashboard_router
from .routes.integrity import router as integrity_router
from .routes.modules import router as modules_router
from .routes.network import router as network_router
from .routes.security import router as security_router
from .routes.settings import router as settings_router
from .routes.vpn import router as vpn_router
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

# WebSocket router is mounted at root level (no prefix)
websocket_router = ws_router
