"""Tests for NotificationDispatcher — event routing to webhook and SMTP channels."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.notifications.dispatcher import NotificationDispatcher, SUPPORTED_EVENT_TYPES


def _make_channel(name="test-webhook", channel_type="webhook", enabled=True,
                  events_json=None, config_json=None):
    """Create a mock NotificationChannel ORM object."""
    channel = MagicMock()
    channel.name = name
    channel.channel_type = channel_type
    channel.enabled = enabled
    channel.events_json = events_json
    channel.config_json = config_json
    return channel


def _make_session_factory(channels=None):
    """Build a mock async session factory that returns given channels."""
    channels = channels or []

    session = AsyncMock()

    async def _execute(query):
        result = MagicMock()
        scalars = MagicMock()
        scalars.all.return_value = channels
        result.scalars.return_value = scalars
        return result

    session.execute = AsyncMock(side_effect=_execute)

    context = AsyncMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)

    factory = MagicMock(return_value=context)
    return factory


class TestDispatchRoutesToWebhook:
    @pytest.mark.asyncio
    async def test_dispatch_routes_to_webhook(self):
        """dispatch() should route to WebhookSender for webhook-type channels."""
        channel = _make_channel(
            name="slack-alerts",
            channel_type="webhook",
            events_json=json.dumps(["alert_critical"]),
            config_json=json.dumps({"url": "https://hooks.slack.com/test"}),
        )
        factory = _make_session_factory(channels=[channel])

        dispatcher = NotificationDispatcher(db_session_factory=factory)
        dispatcher._webhook_sender = AsyncMock()
        dispatcher._webhook_sender.send = AsyncMock(return_value=True)

        payload = {
            "title": "Critical Alert",
            "severity": "critical",
            "description": "Malicious activity detected",
        }

        await dispatcher.dispatch("alert_critical", payload)

        dispatcher._webhook_sender.send.assert_called_once()
        call_args = dispatcher._webhook_sender.send.call_args
        assert call_args[0][0] == "https://hooks.slack.com/test"
        assert call_args[0][1]["event_type"] == "alert_critical"


class TestDispatchRoutesToSMTP:
    @pytest.mark.asyncio
    async def test_dispatch_routes_to_smtp(self):
        """dispatch() should route to SMTPSender for smtp-type channels."""
        channel = _make_channel(
            name="email-alerts",
            channel_type="smtp",
            events_json=json.dumps(["alert_critical"]),
            config_json=json.dumps({
                "to": "admin@example.com",
                "host": "smtp.example.com",
                "port": 587,
                "username": "noreply@example.com",
                "password": "secret",
                "from_addr": "noreply@example.com",
            }),
        )
        factory = _make_session_factory(channels=[channel])

        dispatcher = NotificationDispatcher(db_session_factory=factory)
        dispatcher._smtp_sender = AsyncMock()
        dispatcher._smtp_sender.send = AsyncMock(return_value=True)

        payload = {
            "title": "Critical Alert",
            "severity": "critical",
            "description": "Malicious activity detected",
        }

        await dispatcher.dispatch("alert_critical", payload)

        dispatcher._smtp_sender.send.assert_called_once()
        call_args = dispatcher._smtp_sender.send.call_args
        smtp_config = call_args[0][0]
        assert smtp_config["host"] == "smtp.example.com"
        # 'to' is passed as a separate positional arg to SMTPSender.send()
        to_addr = call_args[0][3]
        assert to_addr == "admin@example.com"


class TestDispatchFiltersEvents:
    @pytest.mark.asyncio
    async def test_dispatch_filters_by_event_type(self):
        """Channels not subscribed to the event type should be skipped."""
        # This channel only subscribes to "feed_updated", not "alert_critical"
        channel = _make_channel(
            name="feed-webhook",
            channel_type="webhook",
            events_json=json.dumps(["feed_updated"]),
            config_json=json.dumps({"url": "https://hooks.example.com/feed"}),
        )
        factory = _make_session_factory(channels=[channel])

        dispatcher = NotificationDispatcher(db_session_factory=factory)
        dispatcher._webhook_sender = AsyncMock()
        dispatcher._webhook_sender.send = AsyncMock(return_value=True)

        payload = {"title": "Critical Alert", "severity": "critical"}

        await dispatcher.dispatch("alert_critical", payload)

        # The webhook sender should NOT have been called since the channel
        # does not subscribe to alert_critical events
        dispatcher._webhook_sender.send.assert_not_called()
