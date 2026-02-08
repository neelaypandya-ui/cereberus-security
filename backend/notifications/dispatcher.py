"""Notification dispatcher — routes events to configured notification channels."""

import json

from sqlalchemy import select

from ..models.notification_channel import NotificationChannel
from ..utils.logging import get_logger
from .smtp import SMTPSender
from .webhook import WebhookSender

logger = get_logger("notifications.dispatcher")

# Supported event types that can trigger notifications
SUPPORTED_EVENT_TYPES = {
    "alert_critical",
    "alert_high",
    "incident_created",
    "playbook_fired",
    "feed_updated",
    "ioc_match",
    "system_error",
}


class NotificationDispatcher:
    """Routes notification events to configured channels.

    Loads enabled notification channels from the database, filters by
    subscribed event types, and dispatches to the appropriate sender
    (webhook or SMTP).
    """

    def __init__(self, db_session_factory) -> None:
        self._session_factory = db_session_factory
        self._webhook_sender = WebhookSender()
        self._smtp_sender = SMTPSender()

    async def dispatch(self, event_type: str, payload: dict) -> None:
        """Dispatch a notification event to all subscribed channels.

        Args:
            event_type: One of the SUPPORTED_EVENT_TYPES.
            payload: Event data to include in the notification.
        """
        if event_type not in SUPPORTED_EVENT_TYPES:
            logger.warning("notification_unknown_event_type", event_type=event_type)
            return

        # Add event_type to payload for context
        payload_with_type = {"event_type": event_type, **payload}

        # Load enabled channels subscribed to this event type
        channels = await self._get_subscribed_channels(event_type)
        if not channels:
            logger.debug("notification_no_channels", event_type=event_type)
            return

        logger.info(
            "notification_dispatching",
            event_type=event_type,
            channel_count=len(channels),
        )

        for channel in channels:
            try:
                await self._send_to_channel(channel, payload_with_type)
            except Exception as exc:
                logger.error(
                    "notification_channel_error",
                    channel_name=channel.name,
                    channel_type=channel.channel_type,
                    error=str(exc),
                )

    async def _get_subscribed_channels(self, event_type: str) -> list:
        """Query the database for enabled channels subscribed to the given event type."""
        try:
            async with self._session_factory() as session:
                result = await session.execute(
                    select(NotificationChannel).where(
                        NotificationChannel.enabled == True  # noqa: E712
                    )
                )
                all_enabled = result.scalars().all()

                # Filter by event subscription
                subscribed = []
                for channel in all_enabled:
                    events = self._parse_events(channel.events_json)
                    if event_type in events or "*" in events:
                        subscribed.append(channel)

                return subscribed
        except Exception as exc:
            logger.error("notification_query_error", error=str(exc))
            return []

    @staticmethod
    def _parse_events(events_json: str | None) -> set[str]:
        """Parse the events_json field into a set of event type strings."""
        if not events_json:
            # No events configured — subscribe to all by default
            return {"*"}
        try:
            events = json.loads(events_json)
            if isinstance(events, list):
                return set(events)
            return {"*"}
        except json.JSONDecodeError:
            return {"*"}

    async def _send_to_channel(self, channel, payload: dict) -> None:
        """Route a notification to the appropriate sender based on channel type."""
        config = {}
        if channel.config_json:
            try:
                config = json.loads(channel.config_json)
            except json.JSONDecodeError:
                logger.error("notification_bad_config", channel_name=channel.name)
                return

        if channel.channel_type == "webhook":
            url = config.get("url", "")
            if not url:
                logger.error("notification_webhook_no_url", channel_name=channel.name)
                return
            extra_headers = config.get("headers")
            await self._webhook_sender.send(url, payload, headers=extra_headers)

        elif channel.channel_type == "smtp":
            to = config.get("to", "")
            subject = self._build_email_subject(payload)
            body_html = self._build_email_body(payload)
            smtp_config = {
                "host": config.get("host", ""),
                "port": config.get("port", 587),
                "username": config.get("username", ""),
                "password": config.get("password", ""),
                "from_addr": config.get("from_addr", ""),
            }
            await self._smtp_sender.send(smtp_config, subject, body_html, to)

        else:
            logger.warning(
                "notification_unsupported_channel_type",
                channel_type=channel.channel_type,
                channel_name=channel.name,
            )

    @staticmethod
    def _build_email_subject(payload: dict) -> str:
        """Build an email subject line from the notification payload."""
        event_type = payload.get("event_type", "notification")
        severity = payload.get("severity", "INFO").upper()
        title = payload.get("title", "Alert")
        return f"[CEREBERUS] [{severity}] {title} ({event_type})"

    @staticmethod
    def _build_email_body(payload: dict) -> str:
        """Build an HTML email body from the notification payload."""
        parts = []
        title = payload.get("title", "")
        description = payload.get("description", "")
        severity = payload.get("severity", "info")
        event_type = payload.get("event_type", "")
        timestamp = payload.get("timestamp", "")
        module = payload.get("module_source", "")

        if title:
            parts.append(f"<h2 style='color: #e6edf3; margin-top: 0;'>{title}</h2>")
        if description:
            parts.append(f"<p>{description}</p>")

        # Details table
        details = []
        if severity:
            color_map = {
                "critical": "#ff4444",
                "high": "#ff8800",
                "medium": "#ffcc00",
                "low": "#00ccff",
                "info": "#888888",
            }
            sev_color = color_map.get(severity, "#888888")
            details.append(
                f"<tr><td style='color: #666; padding: 4px 12px 4px 0;'>Severity</td>"
                f"<td style='color: {sev_color}; font-weight: bold;'>{severity.upper()}</td></tr>"
            )
        if event_type:
            details.append(
                f"<tr><td style='color: #666; padding: 4px 12px 4px 0;'>Event</td>"
                f"<td>{event_type}</td></tr>"
            )
        if module:
            details.append(
                f"<tr><td style='color: #666; padding: 4px 12px 4px 0;'>Module</td>"
                f"<td>{module}</td></tr>"
            )
        if timestamp:
            details.append(
                f"<tr><td style='color: #666; padding: 4px 12px 4px 0;'>Timestamp</td>"
                f"<td>{timestamp}</td></tr>"
            )

        if details:
            parts.append(
                "<table style='border-collapse: collapse; margin-top: 12px;'>"
                + "".join(details)
                + "</table>"
            )

        return "\n".join(parts) if parts else "<p>No details available.</p>"
