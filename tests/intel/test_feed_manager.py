"""Tests for FeedManager — threat intelligence feed polling and IOC ingestion."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.intel.feed_manager import FeedManager


def _make_feed(feed_id=1, name="test-feed", feed_type="virustotal",
               enabled=True, poll_interval=300, config_json=None,
               api_key_encrypted=None, items_count=0):
    """Create a mock ThreatFeed ORM object."""
    feed = MagicMock()
    feed.id = feed_id
    feed.name = name
    feed.feed_type = feed_type
    feed.enabled = enabled
    feed.poll_interval_seconds = poll_interval
    feed.config_json = config_json
    feed.api_key_encrypted = api_key_encrypted
    feed.items_count = items_count
    feed.last_polled = None
    feed.last_success = None
    return feed


def _make_session_factory(feeds=None, iocs_in_db=None):
    """Build a mock async session factory.

    Args:
        feeds: List of mock feed objects to return from ThreatFeed queries.
        iocs_in_db: List of mock IOC objects already present in the DB.
    """
    feeds = feeds or []
    iocs_in_db = iocs_in_db or []

    session = AsyncMock()

    # Track call count to distinguish between different queries
    call_counter = {"count": 0}

    async def _execute(query):
        call_counter["count"] += 1
        result = MagicMock()
        scalars_mock = MagicMock()

        # The first call in start() fetches all enabled feeds
        # Subsequent calls are per-feed lookups or IOC checks
        if hasattr(query, "whereclause") or True:
            # For simplicity, return feeds list for scalars().all()
            # and first feed for scalar_one_or_none()
            scalars_mock.all.return_value = feeds
            if feeds:
                result.scalar_one_or_none = MagicMock(return_value=feeds[0])
            else:
                result.scalar_one_or_none = MagicMock(return_value=None)
            result.scalars.return_value = scalars_mock
        return result

    session.execute = AsyncMock(side_effect=_execute)
    session.commit = AsyncMock()
    session.add = MagicMock()

    # Make the session usable as an async context manager
    context = AsyncMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)

    factory = MagicMock(return_value=context)
    return factory, session


def _make_config():
    """Create a mock config object."""
    config = MagicMock()
    config.secret_key = "test-secret-key"
    return config


class TestFeedManagerStart:
    @pytest.mark.asyncio
    async def test_start_creates_polling_tasks(self):
        """start() should load enabled feeds from DB and create asyncio tasks."""
        feed1 = _make_feed(feed_id=1, poll_interval=60)
        feed2 = _make_feed(feed_id=2, name="feed-2", poll_interval=120)
        factory, session = _make_session_factory(feeds=[feed1, feed2])
        config = _make_config()

        fm = FeedManager(db_session_factory=factory, config=config)

        with patch("backend.intel.feed_manager.asyncio.create_task") as mock_create_task:
            mock_task = MagicMock()
            mock_create_task.return_value = mock_task

            await fm.start()

            # Two feeds means two polling tasks created
            assert mock_create_task.call_count == 2
            assert len(fm._polling_tasks) == 2
            assert fm._running is True


class TestFeedManagerPollFeed:
    @pytest.mark.asyncio
    async def test_poll_feed_dispatches_to_provider(self):
        """_poll_feed() should fetch the feed, dispatch to the provider, and ingest IOCs."""
        feed = _make_feed(
            feed_id=1,
            feed_type="virustotal",
            config_json='{"targets": [{"type": "hash", "value": "abc123"}]}',
            api_key_encrypted=None,
        )
        factory, session = _make_session_factory(feeds=[feed])
        config = _make_config()

        fm = FeedManager(db_session_factory=factory, config=config)

        mock_ioc_result = {
            "ioc_type": "hash",
            "value": "abc123",
            "severity": "high",
            "source": "virustotal",
            "context": {"found": True, "malicious": 10},
        }

        with patch(
            "backend.intel.feed_manager.VirusTotalProvider"
        ) as MockVT:
            mock_provider = AsyncMock()
            mock_provider.lookup_hash = AsyncMock(return_value=mock_ioc_result)
            MockVT.return_value = mock_provider

            await fm._poll_feed(feed_id=1)

            mock_provider.lookup_hash.assert_called_once_with("abc123")


class TestFeedManagerIngestIOCs:
    @pytest.mark.asyncio
    async def test_ingest_iocs_deduplicates(self):
        """_ingest_iocs() should not create duplicate IOCs for the same type+value."""
        # Simulate an existing IOC in the DB
        existing_ioc = MagicMock()
        existing_ioc.ioc_type = "ip"
        existing_ioc.value = "1.2.3.4"
        existing_ioc.last_seen = None
        existing_ioc.context_json = "{}"
        existing_ioc.severity = "medium"
        existing_ioc.active = True

        session = AsyncMock()

        # First call returns existing IOC, second call returns None (new IOC)
        call_counter = {"n": 0}

        async def _execute(query):
            call_counter["n"] += 1
            result = MagicMock()
            # Alternate: first IOC exists, second does not
            if call_counter["n"] == 1:
                result.scalar_one_or_none = MagicMock(return_value=existing_ioc)
            else:
                result.scalar_one_or_none = MagicMock(return_value=None)
            return result

        session.execute = AsyncMock(side_effect=_execute)
        session.commit = AsyncMock()
        session.add = MagicMock()

        context = AsyncMock()
        context.__aenter__ = AsyncMock(return_value=session)
        context.__aexit__ = AsyncMock(return_value=False)
        factory = MagicMock(return_value=context)

        config = _make_config()
        fm = FeedManager(db_session_factory=factory, config=config)

        iocs = [
            {"ioc_type": "ip", "value": "1.2.3.4", "severity": "high", "source": "test"},
            {"ioc_type": "ip", "value": "5.6.7.8", "severity": "medium", "source": "test"},
        ]

        count = await fm._ingest_iocs(iocs, feed_id=1)

        # Both IOCs processed
        assert count == 2
        # Only the second (new) IOC should be added via session.add
        assert session.add.call_count == 1
        # Existing IOC should have been updated (last_seen set)
        assert existing_ioc.last_seen is not None


class TestFeedManagerStop:
    @pytest.mark.asyncio
    async def test_stop_cancels_tasks(self):
        """stop() should cancel all polling tasks and clear the dict."""
        factory, _ = _make_session_factory()
        config = _make_config()
        fm = FeedManager(db_session_factory=factory, config=config)
        fm._running = True

        # Simulate two active tasks
        task1 = MagicMock()
        task2 = MagicMock()
        fm._polling_tasks = {1: task1, 2: task2}

        await fm.stop()

        task1.cancel.assert_called_once()
        task2.cancel.assert_called_once()
        assert fm._running is False
        assert len(fm._polling_tasks) == 0
