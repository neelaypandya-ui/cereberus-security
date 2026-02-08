"""Tests for Network Sentinel module."""

from collections import namedtuple
from unittest.mock import MagicMock, patch

import pytest

from backend.modules.network_sentinel import NetworkSentinel, DEFAULT_SUSPICIOUS_PORTS


# Mimic psutil connection named tuple
SConn = namedtuple("sconn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])
Addr = namedtuple("addr", ["ip", "port"])


def _make_conn(local_ip="127.0.0.1", local_port=8000, remote_ip="", remote_port=None, status="ESTABLISHED", pid=1234, conn_type=1):
    laddr = Addr(local_ip, local_port)
    raddr = Addr(remote_ip, remote_port) if remote_ip else ()
    return SConn(fd=-1, family=2, type=conn_type, laddr=laddr, raddr=raddr, status=status, pid=pid)


class TestNetworkSentinel:
    def setup_method(self):
        self.sentinel = NetworkSentinel(config={
            "poll_interval": 5,
            "suspicious_ports": list(DEFAULT_SUSPICIOUS_PORTS),
        })

    def test_initial_state(self):
        """Sentinel should start with empty caches."""
        assert self.sentinel._connections == []
        assert self.sentinel._flagged == []
        assert self.sentinel._stats == {}
        assert not self.sentinel.running

    def test_is_suspicious_local_port(self):
        """Should flag connections on suspicious local ports."""
        assert self.sentinel._is_suspicious(4444, 80) is True
        assert self.sentinel._is_suspicious(80, 443) is False

    def test_is_suspicious_remote_port(self):
        """Should flag connections to suspicious remote ports."""
        assert self.sentinel._is_suspicious(12345, 1337) is True
        assert self.sentinel._is_suspicious(None, 31337) is True

    def test_is_suspicious_none_ports(self):
        """Should handle None ports without error."""
        assert self.sentinel._is_suspicious(None, None) is False

    def test_parse_connection_established(self):
        """Should correctly parse an established TCP connection."""
        conn = _make_conn("192.168.1.100", 55000, "93.184.216.34", 443, "ESTABLISHED", 5678)
        result = self.sentinel._parse_connection(conn)

        assert result["local_addr"] == "192.168.1.100"
        assert result["local_port"] == 55000
        assert result["remote_addr"] == "93.184.216.34"
        assert result["remote_port"] == 443
        assert result["protocol"] == "tcp"
        assert result["status"] == "ESTABLISHED"
        assert result["pid"] == 5678
        assert result["suspicious"] is False

    def test_parse_connection_suspicious(self):
        """Should flag a connection with a suspicious port."""
        conn = _make_conn("10.0.0.5", 4444, "203.0.113.50", 80, "ESTABLISHED", 9999)
        result = self.sentinel._parse_connection(conn)
        assert result["suspicious"] is True

    def test_parse_connection_listening(self):
        """Should handle a listening connection with no remote addr."""
        conn = _make_conn("0.0.0.0", 4444, status="LISTEN", pid=1111)
        result = self.sentinel._parse_connection(conn)
        assert result["remote_addr"] == ""
        assert result["remote_port"] is None
        assert result["status"] == "LISTEN"
        # 4444 is in suspicious ports
        assert result["suspicious"] is True

    def test_parse_connection_udp(self):
        """Should detect UDP connections (type=2)."""
        conn = _make_conn("0.0.0.0", 53, conn_type=2, status="NONE")
        result = self.sentinel._parse_connection(conn)
        assert result["protocol"] == "udp"

    @patch("backend.modules.network_sentinel.psutil")
    @pytest.mark.asyncio
    async def test_scan_connections(self, mock_psutil):
        """Full scan should populate caches and stats."""
        mock_psutil.net_connections.return_value = [
            _make_conn("192.168.1.1", 55000, "10.0.0.1", 443, "ESTABLISHED", 100),
            _make_conn("0.0.0.0", 80, status="LISTEN", pid=200),
            _make_conn("192.168.1.1", 60000, "10.0.0.2", 4444, "ESTABLISHED", 300),
        ]

        await self.sentinel._scan_connections()

        assert len(self.sentinel._connections) == 3
        assert self.sentinel._stats["total"] == 3
        assert self.sentinel._stats["established"] == 2
        assert self.sentinel._stats["listening"] == 1
        assert self.sentinel._stats["tcp"] == 3
        assert self.sentinel._stats["suspicious"] == 1
        assert len(self.sentinel._flagged) == 1
        assert self.sentinel._flagged[0]["remote_port"] == 4444
        assert self.sentinel._last_scan is not None

    @patch("backend.modules.network_sentinel.psutil")
    @pytest.mark.asyncio
    async def test_start_and_stop(self, mock_psutil):
        """Should start and stop cleanly."""
        mock_psutil.net_connections.return_value = []

        await self.sentinel.start()
        assert self.sentinel.running is True
        assert self.sentinel.health_status == "running"

        await self.sentinel.stop()
        assert self.sentinel.running is False
        assert self.sentinel.health_status == "stopped"

    @patch("backend.modules.network_sentinel.psutil")
    @pytest.mark.asyncio
    async def test_health_check(self, mock_psutil):
        """Health check should return current stats."""
        mock_psutil.net_connections.return_value = [
            _make_conn("127.0.0.1", 8000, "10.0.0.1", 443, "ESTABLISHED"),
        ]

        await self.sentinel._scan_connections()
        health = await self.sentinel.health_check()

        assert health["status"] == "initialized"  # not started via start()
        assert health["details"]["total_connections"] == 1
        assert health["details"]["flagged_count"] == 0

    def test_get_live_connections_empty(self):
        """get_live_connections should return empty list initially."""
        assert self.sentinel.get_live_connections() == []

    def test_get_stats_empty(self):
        """get_stats should return empty dict with last_scan None."""
        stats = self.sentinel.get_stats()
        assert stats["last_scan"] is None

    def test_get_flagged_connections_empty(self):
        """get_flagged_connections should return empty list initially."""
        assert self.sentinel.get_flagged_connections() == []

    def test_custom_suspicious_ports(self):
        """Should use custom suspicious ports from config."""
        sentinel = NetworkSentinel(config={"suspicious_ports": [9999, 7777]})
        assert sentinel._is_suspicious(9999, None) is True
        assert sentinel._is_suspicious(None, 7777) is True
        assert sentinel._is_suspicious(4444, None) is False  # not in custom list
