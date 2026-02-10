"""Alert dispatch manager.

Routes alerts to various outputs: database, WebSocket broadcast,
desktop notifications, and webhooks.
"""

import hashlib
import json
import time
from collections import deque
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
        self._alert_history: deque = deque(maxlen=1000)
        self._dedup_cache: dict[str, float] = {}
        self._dedup_ttl: float = 300.0

        # Phase 7/8 integrations
        self._playbook_executor = None
        self._notification_dispatcher = None

        # Phase 15: Bond Sword integration
        self._commander_bond = None

    def set_db_session_factory(self, factory) -> None:
        """Set the async session factory for database persistence."""
        self._db_session_factory = factory

    def set_playbook_executor(self, executor) -> None:
        """Attach the PlaybookExecutor for automated alert-triggered responses."""
        self._playbook_executor = executor

    def set_notification_dispatcher(self, dispatcher) -> None:
        """Attach the NotificationDispatcher for multi-channel alerts."""
        self._notification_dispatcher = dispatcher

    def set_commander_bond(self, bond) -> None:
        """Attach Commander Bond for Sword Protocol evaluation on alerts."""
        self._commander_bond = bond

    def _alert_dedup_key(self, severity: str, module_source: str, title: str, details: dict | None) -> str:
        """Create an MD5 hash deduplication key from alert fields.

        Uses severity + module + title only (excludes volatile details like
        anomaly scores) so repeated alerts of the same type are properly deduped.
        """
        raw = f"{severity}|{module_source}|{title}"
        return hashlib.md5(raw.encode("utf-8")).hexdigest()

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

        # Deduplication check
        dedup_key = self._alert_dedup_key(severity, module_source, title, details)
        now = time.time()

        # Prune expired dedup cache entries (limit to 100 per call)
        expired_keys = [
            k for k in list(self._dedup_cache.keys())[:100]
            if now - self._dedup_cache[k] > self._dedup_ttl
        ]
        for k in expired_keys:
            del self._dedup_cache[k]

        if dedup_key in self._dedup_cache and now - self._dedup_cache[dedup_key] <= self._dedup_ttl:
            logger.info("echo_suppressed", severity=severity, module=module_source, title=title)
            return alert

        self._dedup_cache[dedup_key] = now

        self._alert_history.append(alert)
        logger.info(
            "alert_created",
            severity=severity,
            module=module_source,
            title=title,
        )

        # Persist to database
        alert_id = await self._persist_to_db(alert)
        if alert_id is not None:
            alert["id"] = alert_id

        # Dispatch to all channels
        await self._broadcast_ws(alert)
        await self._send_desktop_notification(alert)
        await self._send_webhook(alert)

        # Feed to playbook executor for automated response
        if self._playbook_executor:
            try:
                event = {
                    "event_type": "alert_severity",
                    "source_module": module_source,
                    "severity": severity,
                    "details": details or {},
                    "title": title,
                }
                await self._playbook_executor.evaluate_event(event)
            except Exception as e:
                logger.error("playbook_eval_on_alert_failed", error=str(e))

        # Dispatch to notification channels
        if self._notification_dispatcher:
            try:
                event_type = f"alert_{severity}" if severity in ("critical", "high") else None
                if event_type:
                    await self._notification_dispatcher.dispatch(event_type, alert)
            except Exception as e:
                logger.error("notification_dispatch_failed", error=str(e))

        # Phase 15: Evaluate via Sword Protocol (avoid recursion — skip sword's own alerts)
        if self._commander_bond and module_source != "sword_protocol":
            try:
                event = {
                    "event_type": "alert",
                    "source_module": module_source,
                    "module_source": module_source,
                    "severity": severity,
                    "title": title,
                    "details": details or {},
                    "alert_id": alert.get("id"),
                }
                await self._commander_bond.evaluate_alert(event)
            except Exception as e:
                logger.error("sword_eval_on_alert_failed", error=str(e))

        return alert

    async def _persist_to_db(self, alert: dict) -> Optional[int]:
        """Write alert to the database and return its ID."""
        if not self._db_session_factory:
            return None

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
                await session.refresh(db_alert)
                return db_alert.id
        except Exception as e:
            logger.error("alert_db_persist_failed", error=str(e))
            return None

    async def resolve_alert(self, alert_id: int, resolved_by: str) -> None:
        """Mark an alert as resolved by Bond/Sword and broadcast via WebSocket."""
        if not self._db_session_factory:
            return

        try:
            from ..models.alert import Alert

            now = datetime.now(timezone.utc)
            async with self._db_session_factory() as session:
                from sqlalchemy import select
                result = await session.execute(select(Alert).where(Alert.id == alert_id))
                db_alert = result.scalar_one_or_none()
                if not db_alert:
                    logger.warning("resolve_alert_not_found", alert_id=alert_id)
                    return
                db_alert.acknowledged = True
                db_alert.resolved_at = now
                db_alert.resolved_by = resolved_by
                await session.commit()

            logger.info("alert_resolved_by_sword", alert_id=alert_id, resolved_by=resolved_by)

            # Broadcast resolution via WebSocket
            await self._broadcast_ws(None, message_override={
                "type": "alert_resolved",
                "data": {
                    "alert_id": alert_id,
                    "resolved_by": resolved_by,
                    "resolved_at": now.isoformat(),
                },
            })
        except Exception as e:
            logger.error("resolve_alert_failed", alert_id=alert_id, error=str(e))

    async def _broadcast_ws(self, alert: dict | None, message_override: dict | None = None) -> None:
        """Broadcast alert or custom message to all connected WebSocket clients."""
        if message_override:
            message = json.dumps(message_override)
        else:
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
        """Send a desktop notification via plyer. Disabled — use WebSocket/webhook instead."""
        return

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
