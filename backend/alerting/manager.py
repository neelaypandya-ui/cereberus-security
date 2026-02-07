"""Alert dispatch manager.

Routes alerts to various outputs: database, WebSocket broadcast,
desktop notifications, and webhooks.
"""

import json
from datetime import datetime, timezone
from typing import Optional

import httpx

from ..utils.logging import get_logger

logger = get_logger("alerting.manager")


class AlertManager:
    """Manages alert creation, routing, and dispatch."""

    def __init__(
        self,
        desktop_notifications: bool = True,
        webhook_url: Optional[str] = None,
        db_session_factory=None,
    ):
        self._desktop_notifications = desktop_notifications
        self._webhook_url = webhook_url
        self._db_session_factory = db_session_factory
        self._ws_connections: list = []  # WebSocket connections for broadcasting
        self._alert_history: list[dict] = []

    def set_db_session_factory(self, factory) -> None:
        """Set the async session factory for database persistence."""
        self._db_session_factory = factory

    def register_ws(self, ws) -> None:
        """Register a WebSocket connection for alert broadcasting."""
        self._ws_connections.append(ws)

    def unregister_ws(self, ws) -> None:
        """Unregister a WebSocket connection."""
        if ws in self._ws_connections:
            self._ws_connections.remove(ws)

    async def create_alert(
        self,
        severity: str,
        module_source: str,
        title: str,
        description: str,
        details: dict | None = None,
        vpn_status: str | None = None,
        interface_name: str | None = None,
    ) -> dict:
        """Create and dispatch an alert.

        Args:
            severity: critical, high, medium, low, info
            module_source: Which module generated the alert
            title: Short alert title
            description: Detailed description
            details: Additional structured data
            vpn_status: VPN state at time of event
            interface_name: Network interface involved
        """
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "module_source": module_source,
            "title": title,
            "description": description,
            "details": details,
            "vpn_status": vpn_status,
            "interface_name": interface_name,
            "acknowledged": False,
        }

        self._alert_history.append(alert)
        logger.info(
            "alert_created",
            severity=severity,
            module=module_source,
            title=title,
        )

        # Persist to database
        await self._persist_to_db(alert)

        # Dispatch to all channels
        await self._broadcast_ws(alert)
        await self._send_desktop_notification(alert)
        await self._send_webhook(alert)

        return alert

    async def _persist_to_db(self, alert: dict) -> None:
        """Write alert to the database."""
        if not self._db_session_factory:
            return

        try:
            from ..models.alert import Alert

            async with self._db_session_factory() as session:
                db_alert = Alert(
                    severity=alert["severity"],
                    module_source=alert["module_source"],
                    title=alert["title"],
                    description=alert["description"],
                    details_json=json.dumps(alert.get("details")) if alert.get("details") else None,
                    vpn_status_at_event=alert.get("vpn_status"),
                    interface_name=alert.get("interface_name"),
                    acknowledged=False,
                )
                session.add(db_alert)
                await session.commit()
        except Exception as e:
            logger.error("alert_db_persist_failed", error=str(e))

    async def _broadcast_ws(self, alert: dict) -> None:
        """Broadcast alert to all connected WebSocket clients."""
        message = json.dumps({"type": "alert", "data": alert})
        disconnected = []

        for ws in self._ws_connections:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)

        for ws in disconnected:
            self._ws_connections.remove(ws)

    async def _send_desktop_notification(self, alert: dict) -> None:
        """Send a desktop notification via plyer."""
        if not self._desktop_notifications:
            return

        try:
            from plyer import notification
            notification.notify(
                title=f"CEREBERUS [{alert['severity'].upper()}]",
                message=f"{alert['title']}\n{alert['description'][:200]}",
                app_name="Cereberus",
                timeout=10,
            )
        except Exception as e:
            logger.debug("desktop_notification_failed", error=str(e))

    async def _send_webhook(self, alert: dict) -> None:
        """Send alert to configured webhook URL."""
        if not self._webhook_url:
            return

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    self._webhook_url,
                    json=alert,
                    headers={"Content-Type": "application/json"},
                )
        except Exception as e:
            logger.error("webhook_send_failed", error=str(e), url=self._webhook_url)

    def get_recent_alerts(self, limit: int = 50) -> list[dict]:
        """Get recent alerts from memory cache."""
        return list(reversed(self._alert_history[-limit:]))
