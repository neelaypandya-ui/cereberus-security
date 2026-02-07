"""Tests for the Resource Monitor module."""

import asyncio
from collections import namedtuple
from unittest.mock import MagicMock, patch

import pytest

from backend.modules.resource_monitor import ResourceMonitor


def mock_cpu_percent(interval=None):
    return 45.0


def mock_virtual_memory():
    VM = namedtuple("VM", ["percent", "used", "total"])
    return VM(percent=60.0, used=8 * 1024**3, total=16 * 1024**3)


def mock_disk_usage(path):
    DU = namedtuple("DU", ["percent", "used", "total"])
    return DU(percent=55.0, used=200 * 1024**3, total=500 * 1024**3)


def mock_net_io_counters():
    NIO = namedtuple("NIO", ["bytes_sent", "bytes_recv"])
    return NIO(bytes_sent=1_000_000, bytes_recv=5_000_000)


@pytest.fixture
def monitor():
    return ResourceMonitor(config={
        "poll_interval": 60,
        "cpu_threshold": 90.0,
        "memory_threshold": 85.0,
        "disk_threshold": 90.0,
    })


class TestResourceMonitorBasic:
    def test_init_defaults(self, monitor):
        assert monitor._poll_interval == 60
        assert monitor._cpu_threshold == 90.0
        assert monitor._memory_threshold == 85.0
        assert monitor._current is None

    def test_get_current_empty(self, monitor):
        assert monitor.get_current() == {}

    def test_get_history_empty(self, monitor):
        assert monitor.get_history() == []

    def test_get_alerts_empty(self, monitor):
        assert monitor.get_alerts() == []


class TestResourceSnapshot:
    @pytest.mark.asyncio
    async def test_take_snapshot(self, monitor):
        with patch("psutil.cpu_percent", mock_cpu_percent), \
             patch("psutil.virtual_memory", mock_virtual_memory), \
             patch("psutil.disk_usage", mock_disk_usage), \
             patch("psutil.net_io_counters", mock_net_io_counters):
            await monitor._take_snapshot()

        current = monitor.get_current()
        assert current["cpu_percent"] == 45.0
        assert current["memory_percent"] == 60.0
        assert current["disk_percent"] == 55.0
        assert current["net_bytes_sent"] == 1_000_000
        assert current["alert_triggered"] is False

    @pytest.mark.asyncio
    async def test_history_accumulates(self, monitor):
        with patch("psutil.cpu_percent", mock_cpu_percent), \
             patch("psutil.virtual_memory", mock_virtual_memory), \
             patch("psutil.disk_usage", mock_disk_usage), \
             patch("psutil.net_io_counters", mock_net_io_counters):
            await monitor._take_snapshot()
            await monitor._take_snapshot()
            await monitor._take_snapshot()

        history = monitor.get_history(limit=10)
        assert len(history) == 3


class TestThresholdAlerts:
    @pytest.mark.asyncio
    async def test_cpu_threshold_breach(self, monitor):
        def high_cpu(interval=None):
            return 95.0

        with patch("psutil.cpu_percent", high_cpu), \
             patch("psutil.virtual_memory", mock_virtual_memory), \
             patch("psutil.disk_usage", mock_disk_usage), \
             patch("psutil.net_io_counters", mock_net_io_counters):
            await monitor._take_snapshot()

        alerts = monitor.get_alerts()
        assert len(alerts) == 1
        assert any("CPU" in b for b in alerts[0]["breaches"])

    @pytest.mark.asyncio
    async def test_no_alert_under_threshold(self, monitor):
        with patch("psutil.cpu_percent", mock_cpu_percent), \
             patch("psutil.virtual_memory", mock_virtual_memory), \
             patch("psutil.disk_usage", mock_disk_usage), \
             patch("psutil.net_io_counters", mock_net_io_counters):
            await monitor._take_snapshot()

        alerts = monitor.get_alerts()
        assert len(alerts) == 0


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_health_check(self, monitor):
        health = await monitor.health_check()
        assert health["status"] == "initialized"
        assert "details" in health
