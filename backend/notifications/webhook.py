"""Webhook notification sender — supports generic, Slack, and Discord formats."""

import json

import httpx

from ..utils.logging import get_logger

logger = get_logger("notifications.webhook")


class WebhookSender:
    """Sends notifications via HTTP webhooks.

    Auto-detects Slack and Discord webhook URLs and formats the payload
    accordingly. Falls back to raw JSON POST for generic webhooks.
    """

    async def send(
        self, url: str, payload: dict, headers: dict | None = None
    ) -> bool:
        """Send a notification payload to a webhook URL.

        Args:
            url: The webhook endpoint URL.
            payload: The notification data to send.
            headers: Optional additional HTTP headers.

        Returns:
            True if the webhook responded successfully, False otherwise.
        """
        send_headers = {"Content-Type": "application/json"}
        if headers:
            send_headers.update(headers)

        # Format payload for specific platforms
        body = self._format_payload(url, payload)

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(url, json=body, headers=send_headers)
                response.raise_for_status()
                logger.info("webhook_sent", url=url, status=response.status_code)
                return True
        except httpx.HTTPStatusError as exc:
            logger.error(
                "webhook_http_error",
                url=url,
                status=exc.response.status_code,
                body=exc.response.text[:500],
            )
            return False
        except Exception as exc:
            logger.error("webhook_send_error", url=url, error=str(exc))
            return False

    def _format_payload(self, url: str, payload: dict) -> dict:
        """Format the payload based on the webhook platform.

        Detects Slack and Discord URLs and wraps the payload in the
        platform-specific message format.
        """
        message = self._build_message_text(payload)

        if "hooks.slack.com" in url:
            return {"text": message}

        if "discord.com" in url:
            return {"content": message}

        # Generic webhook — send raw payload with a summary text field
        return {
            "text": message,
            **payload,
        }

    def _build_message_text(self, payload: dict) -> str:
        """Build a human-readable message string from the notification payload."""
        event_type = payload.get("event_type", "notification")
        severity = payload.get("severity", "info")
        title = payload.get("title", "Cereberus Alert")
        description = payload.get("description", "")
        timestamp = payload.get("timestamp", "")

        parts = [
            f"[CEREBERUS] {severity.upper()}: {title}",
        ]
        if description:
            parts.append(description)
        if event_type:
            parts.append(f"Event: {event_type}")
        if timestamp:
            parts.append(f"Time: {timestamp}")

        return "\n".join(parts)
