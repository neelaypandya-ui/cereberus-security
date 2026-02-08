"""Real-time WebSocket event feed."""

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ...config import get_config
from ...dependencies import (
    get_alert_manager,
    get_behavioral_baseline,
    get_ensemble_detector,
    get_network_sentinel,
    get_resource_monitor,
    get_threat_forecaster,
    get_threat_intelligence,
    get_vpn_guardian,
)
from ...utils.logging import get_logger
from ...utils.security import decode_access_token

logger = get_logger("websocket.events")

router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("ws_client_connected", total=len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info("ws_client_disconnected", total=len(self.active_connections))

    async def broadcast(self, message: dict) -> None:
        """Broadcast a message to all connected clients."""
        text = json.dumps(message)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(text)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket endpoint for real-time event streaming.

    Sends events in JSON format:
    {
        "type": "alert" | "vpn_status" | "event" | "heartbeat" | "network_stats" | "threat_level",
        "data": { ... },
        "timestamp": "ISO 8601"
    }
    """
    # Authenticate via JWT token in query params or session cookie
    token = websocket.query_params.get("token") or websocket.cookies.get("cereberus_session")
    if not token:
        await websocket.close(code=4001)
        return
    config = get_config()
    payload = decode_access_token(token, config.secret_key, config.jwt_algorithm)
    if payload is None:
        await websocket.close(code=4001)
        return

    # Check burn list — reject revoked tokens
    from ...api.routes.auth import is_token_burned
    from ...database import get_session_factory
    factory = get_session_factory(config)
    async with factory() as db:
        if await is_token_burned(token, db):
            await websocket.close(code=4001)
            return

    await manager.connect(websocket)

    # Register with alert manager for broadcasting
    alert_mgr = get_alert_manager()
    alert_mgr.register_ws(websocket)

    try:
        while True:
            # Send periodic heartbeat with VPN status
            vpn = get_vpn_guardian()
            status = vpn.detector.state.to_dict()

            await websocket.send_text(json.dumps({
                "type": "vpn_status",
                "data": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

            # Send network stats
            try:
                sentinel = get_network_sentinel()
                net_stats = sentinel.get_stats()
                await websocket.send_text(json.dumps({
                    "type": "network_stats",
                    "data": net_stats,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
            except Exception:
                pass

            # Send anomaly alert if detected
            try:
                sentinel = get_network_sentinel()
                anomaly = sentinel.get_anomaly_result()
                if anomaly and anomaly.get("is_anomaly"):
                    await websocket.send_text(json.dumps({
                        "type": "anomaly_alert",
                        "data": anomaly,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }))
            except Exception:
                pass

            # Send resource stats
            try:
                rm = get_resource_monitor()
                current = rm.get_current()
                if current:
                    await websocket.send_text(json.dumps({
                        "type": "resource_stats",
                        "data": current,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }))
            except Exception:
                pass

            # Send threat level
            try:
                ti = get_threat_intelligence()
                threat_level = ti.get_threat_level()
                await websocket.send_text(json.dumps({
                    "type": "threat_level",
                    "data": {"level": threat_level},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
            except Exception:
                pass

            # Send AI status (ensemble health, baseline progress, drift)
            try:
                ensemble = get_ensemble_detector()
                baseline = get_behavioral_baseline()
                last_result = ensemble.get_last_result()
                await websocket.send_text(json.dumps({
                    "type": "ai_status",
                    "data": {
                        "ensemble_score": last_result.get("ensemble_score") if last_result else None,
                        "is_anomaly": last_result.get("is_anomaly") if last_result else None,
                        "drift_score": ensemble.get_drift_score(),
                        "baseline_progress": baseline.get_learning_progress(),
                        "detector_scores": last_result.get("detector_scores") if last_result else {},
                    },
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
            except Exception:
                pass

            # Send prediction update
            try:
                forecaster = get_threat_forecaster()
                if forecaster.initialized and forecaster.model is not None:
                    rm = get_resource_monitor()
                    history = rm.get_history(limit=60)
                    if len(history) >= 30:
                        trend = await forecaster.predict_trend(history, steps=6)
                        alerts = forecaster.check_forecast_alerts(trend)
                        await websocket.send_text(json.dumps({
                            "type": "prediction_update",
                            "data": {
                                "predictions": trend,
                                "forecast_alerts": alerts,
                            },
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }))
            except Exception:
                pass

            # Wait for client messages or timeout for next heartbeat
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
                # Handle client commands (future: subscribe to specific events)
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await websocket.send_text(json.dumps({
                            "type": "pong",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }))
                except json.JSONDecodeError:
                    pass
            except asyncio.TimeoutError:
                # No message from client, continue loop
                pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("ws_error", error=str(e))
    finally:
        manager.disconnect(websocket)
        alert_mgr.unregister_ws(websocket)
