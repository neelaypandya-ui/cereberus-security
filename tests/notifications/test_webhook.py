"""Tests for WebhookSender — HTTP webhook delivery and Slack formatting."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.notifications.webhook import WebhookSender


def _mock_httpx_response(status_code=200):
    """Create a mock httpx Response."""
    response = MagicMock()
    response.status_code = status_code
    response.raise_for_status = MagicMock()
    return response


class TestSendWebhook:
    @pytest.mark.asyncio
    async def test_send_webhook(self):
        """send() should POST the payload to the given URL via httpx."""
        mock_response = _mock_httpx_response(status_code=200)

        sender = WebhookSender()

        with patch("backend.notifications.webhook.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await sender.send(
                url="https://hooks.example.com/webhook",
                payload={
                    "event_type": "alert_critical",
                    "title": "Test Alert",
                    "severity": "critical",
                },
            )

        assert result is True
        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert call_kwargs[0][0] == "https://hooks.example.com/webhook"


class TestSlackFormatting:
    @pytest.mark.asyncio
    async def test_slack_formatting(self):
        """Slack webhook URLs should produce a payload with a 'text' key only."""
        mock_response = _mock_httpx_response(status_code=200)

        sender = WebhookSender()

        with patch("backend.notifications.webhook.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            await sender.send(
                url="https://hooks.slack.com/services/T00/B00/xxx",
                payload={
                    "event_type": "alert_high",
                    "title": "High Alert",
                    "severity": "high",
                    "description": "Suspicious activity",
                },
            )

        # Verify the Slack-formatted payload
        call_kwargs = mock_client.post.call_args
        body = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs[0][1]
        # Slack format should have only a "text" key
        assert "text" in body
        assert "HIGH" in body["text"]
        assert "High Alert" in body["text"]
        # Should NOT have other payload keys directly (unlike generic webhook)
        assert "event_type" not in body
