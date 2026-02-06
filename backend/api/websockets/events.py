"""Real-time WebSocket event feed."""

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ...dependencies import get_alert_manager, get_network_sentinel, get_vpn_guardian
from ...utils.logging import get_logger

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
        "type": "alert" | "vpn_status" | "event" | "heartbeat",
        "data": { ... },
        "timestamp": "ISO 8601"
    }
    """
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
