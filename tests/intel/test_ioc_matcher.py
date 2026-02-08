"""Tests for IOCMatcher — IOC database matching with TTL cache."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.intel.ioc_matcher import IOCMatcher, _CACHE_TTL


def _make_ioc(ioc_type="ip", value="1.2.3.4", severity="high", source="test",
              first_seen=None, last_seen=None, tags_json=None,
              context_json=None, feed_id=1):
    """Create a mock IOC ORM object."""
    ioc = MagicMock()
    ioc.ioc_type = ioc_type
    ioc.value = value
    ioc.severity = severity
    ioc.source = source
    ioc.first_seen = first_seen
    ioc.last_seen = last_seen
    ioc.tags_json = tags_json
    ioc.context_json = context_json
    ioc.feed_id = feed_id
    ioc.active = True
    return ioc


def _make_session_factory(iocs=None):
    """Build a mock async session factory that returns given IOCs from queries."""
    iocs = iocs or []

    session = AsyncMock()

    async def _execute(query):
        result = MagicMock()
        scalars = MagicMock()
        scalars.all.return_value = iocs
        result.scalars.return_value = scalars
        return result

    session.execute = AsyncMock(side_effect=_execute)

    context = AsyncMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)

    factory = MagicMock(return_value=context)
    return factory, session


class TestCheckIPs:
    @pytest.mark.asyncio
    async def test_check_ips_returns_matches(self):
        """check_ips should return matching IOC dictionaries for known IPs."""
        mock_ioc = _make_ioc(ioc_type="ip", value="10.0.0.1", severity="critical")
        factory, session = _make_session_factory(iocs=[mock_ioc])

        matcher = IOCMatcher(db_session_factory=factory)
        matches = await matcher.check_ips(["10.0.0.1"])

        assert len(matches) == 1
        assert matches[0]["value"] == "10.0.0.1"
        assert matches[0]["severity"] == "critical"
        assert matches[0]["ioc_type"] == "ip"

    @pytest.mark.asyncio
    async def test_check_ips_cache_hit(self):
        """Second call within TTL should return cached results without DB query."""
        mock_ioc = _make_ioc(ioc_type="ip", value="10.0.0.1")
        factory, session = _make_session_factory(iocs=[mock_ioc])

        matcher = IOCMatcher(db_session_factory=factory)

        # First call — populates cache
        matches1 = await matcher.check_ips(["10.0.0.1"])
        assert len(matches1) == 1

        # Reset the session mock call count
        session.execute.reset_mock()

        # Second call — should hit cache, no DB query
        matches2 = await matcher.check_ips(["10.0.0.1"])
        assert len(matches2) == 1
        session.execute.assert_not_called()


class TestCheckDomains:
    @pytest.mark.asyncio
    async def test_check_domains_no_match(self):
        """check_domains should return empty list when no IOCs match."""
        factory, session = _make_session_factory(iocs=[])

        matcher = IOCMatcher(db_session_factory=factory)
        matches = await matcher.check_domains(["safe-domain.com"])

        assert matches == []


class TestCacheExpiry:
    @pytest.mark.asyncio
    async def test_cache_expiry(self):
        """After TTL expires, cache should be refreshed from DB."""
        mock_ioc = _make_ioc(ioc_type="ip", value="192.168.1.1")
        factory, session = _make_session_factory(iocs=[mock_ioc])

        matcher = IOCMatcher(db_session_factory=factory)

        # First call — populates cache
        await matcher.check_ips(["192.168.1.1"])
        assert session.execute.call_count == 1

        # Manually expire the cache entry by backdating the timestamp
        key = ("ip", "192.168.1.1")
        if key in matcher._cache:
            result, _ = matcher._cache[key]
            matcher._cache[key] = (result, time.monotonic() - _CACHE_TTL - 1)

        # Next call should query the DB again since cache is expired
        await matcher.check_ips(["192.168.1.1"])
        assert session.execute.call_count == 2
