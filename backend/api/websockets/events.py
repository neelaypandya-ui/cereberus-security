"""Real-time WebSocket event feed."""

import asyncio
import json
import time
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
    """Manages active WebSocket connections with backpressure and heartbeat."""

    def __init__(self, max_connections: int = 100, queue_size: int = 50, heartbeat_interval: int = 30):
        self._connections: dict[WebSocket, asyncio.Queue] = {}
        self._writer_tasks: dict[WebSocket, asyncio.Task] = {}
        self._max_connections = max_connections
        self._queue_size = queue_size
        self._heartbeat_interval = heartbeat_interval

    async def connect(self, websocket: WebSocket) -> bool:
        """Accept connection if under limit. Returns False if rejected."""
        if len(self._connections) >= self._max_connections:
            await websocket.close(code=1013)  # Try Again Later
            logger.warning("ws_connection_rejected", reason="max_connections", total=len(self._connections))
            return False
        await websocket.accept()
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
        self._connections[websocket] = queue
        # Start writer task for this connection
        task = asyncio.create_task(self._writer(websocket, queue))
        self._writer_tasks[websocket] = task
        logger.info("ws_client_connected", total=len(self._connections))
        return True

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove connection and cancel its writer task."""
        self._connections.pop(websocket, None)
        task = self._writer_tasks.pop(websocket, None)
        if task and not task.done():
            task.cancel()
        try:
            await websocket.close()
        except Exception as e:
            logger.debug("ws_close_failed", error=str(e))
        logger.info("ws_client_disconnected", total=len(self._connections))

    async def broadcast(self, message: dict) -> None:
        """Non-blocking broadcast: enqueue message to all connections."""
        text = json.dumps(message)
        disconnected = []
        for ws, queue in list(self._connections.items()):
            try:
                queue.put_nowait(text)
            except asyncio.QueueFull:
                # Client can't keep up — disconnect
                disconnected.append(ws)
                logger.warning("ws_client_backpressure_disconnect")
        for ws in disconnected:
            await self.disconnect(ws)

    async def close_all(self) -> None:
        """Close all connections gracefully."""
        for ws in list(self._connections.keys()):
            await self.disconnect(ws)

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def _writer(self, websocket: WebSocket, queue: asyncio.Queue) -> None:
        """Per-connection writer coroutine that drains the queue."""
        last_activity = time.monotonic()
        try:
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=self._heartbeat_interval)
                    await websocket.send_text(message)
                    last_activity = time.monotonic()
                except asyncio.TimeoutError:
                    # No messages for heartbeat_interval — send ping
                    try:
                        await websocket.send_text(json.dumps({
                            "type": "heartbeat",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }))
                        last_activity = time.monotonic()
                    except Exception as e:
                        logger.debug("ws_heartbeat_failed", error=str(e))
                        break
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.debug("ws_writer_error", error=str(e))
            return


config = get_config()
manager = ConnectionManager(
    max_connections=config.ws_max_connections,
    queue_size=config.ws_queue_size,
    heartbeat_interval=config.ws_heartbeat_interval,
)


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket endpoint for real-time event streaming.

    Sends events in JSON format:
    {
        "type": "batch_update" | "alert" | "vpn_status" | "event" | "heartbeat" | "network_stats" | "threat_level",
        "data": { ... },
        "timestamp": "ISO 8601"
    }
    """
    # Authenticate via JWT token in query params or session cookie
    token = websocket.query_params.get("token") or websocket.cookies.get("cereberus_session")
    if not token:
        await websocket.close(code=4001)
        return
    cfg = get_config()
    payload = decode_access_token(token, cfg.secret_key, cfg.jwt_algorithm)
    if payload is None:
        await websocket.close(code=4001)
        return

    # Check burn list — reject revoked tokens
    from ...api.routes.auth import is_token_burned
    from ...database import get_session_factory
    factory = get_session_factory(cfg)
    async with factory() as db:
        if await is_token_burned(token, db):
            await websocket.close(code=4001)
            return

    connected = await manager.connect(websocket)
    if not connected:
        return

    # Send immediate ack so frontend shows LIVE before data collection
    await websocket.send_text(json.dumps({
        "type": "connected",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }))

    # Register with alert manager for broadcasting
    alert_mgr = get_alert_manager()
    alert_mgr.register_ws(websocket)

    try:
        while True:
            # Collect all data into a single batch message
            batch_data = {}
            timestamp = datetime.now(timezone.utc).isoformat()

            # VPN status
            try:
                vpn = get_vpn_guardian()
                batch_data["vpn_status"] = vpn.detector.state.to_dict()
            except Exception as e:
                logger.debug("ws_vpn_status_failed", error=str(e))

            # Network stats
            try:
                sentinel = get_network_sentinel()
                batch_data["network_stats"] = sentinel.get_stats()
                anomaly = sentinel.get_anomaly_result()
                if anomaly and anomaly.get("is_anomaly"):
                    batch_data["anomaly_alert"] = anomaly
            except Exception as e:
                logger.debug("ws_network_stats_failed", error=str(e))

            # Resource stats
            try:
                rm = get_resource_monitor()
                current = rm.get_current()
                if current:
                    batch_data["resource_stats"] = current
            except Exception as e:
                logger.debug("ws_resource_stats_failed", error=str(e))

            # Threat level
            try:
                ti = get_threat_intelligence()
                batch_data["threat_level"] = {"level": ti.get_threat_level()}
            except Exception as e:
                logger.debug("ws_threat_level_failed", error=str(e))

            # AI status
            try:
                ensemble = get_ensemble_detector()
                baseline = get_behavioral_baseline()
                last_result = ensemble.get_last_result()
                batch_data["ai_status"] = {
                    "ensemble_score": last_result.get("ensemble_score") if last_result else None,
                    "is_anomaly": last_result.get("is_anomaly") if last_result else None,
                    "drift_score": ensemble.get_drift_score(),
                    "baseline_progress": baseline.get_learning_progress(),
                    "detector_scores": last_result.get("detector_scores") if last_result else {},
                }
            except Exception as e:
                logger.debug("ws_ai_status_failed", error=str(e))

            # Prediction update
            try:
                forecaster = get_threat_forecaster()
                if forecaster.initialized and forecaster.model is not None:
                    rm = get_resource_monitor()
                    history = rm.get_history(limit=60)
                    if len(history) >= 30:
                        trend = await forecaster.predict_trend(history, steps=6)
                        alerts = forecaster.check_forecast_alerts(trend)
                        batch_data["prediction_update"] = {
                            "predictions": trend,
                            "forecast_alerts": alerts,
                        }
            except Exception as e:
                logger.debug("ws_prediction_failed", error=str(e))

            # Send batch
            if batch_data:
                await websocket.send_text(json.dumps({
                    "type": "batch_update",
                    "data": batch_data,
                    "timestamp": timestamp,
                }))

                # Also send individual messages for backward compat
                for msg_type, data in batch_data.items():
                    await websocket.send_text(json.dumps({
                        "type": msg_type,
                        "data": data,
                        "timestamp": timestamp,
                    }))

            # Wait for client messages or timeout
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await websocket.send_text(json.dumps({
                            "type": "pong",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }))
                except json.JSONDecodeError:
                    logger.debug("ws_invalid_json_from_client")
            except asyncio.TimeoutError:
                pass  # Expected — no client message within timeout

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("ws_error", error=str(e))
    finally:
        await manager.disconnect(websocket)
        alert_mgr.unregister_ws(websocket)
