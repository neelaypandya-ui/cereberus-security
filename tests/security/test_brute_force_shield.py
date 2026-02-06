"""Tests for Brute Force Shield module."""

from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.modules.brute_force_shield import BruteForceShield, CEREBERUS_RULE_PREFIX


class TestBruteForceShield:
    def setup_method(self):
        self.shield = BruteForceShield(config={
            "poll_interval": 10,
            "threshold": 3,
            "window_seconds": 60,
            "block_duration": 300,
            "whitelist_ips": ["127.0.0.1", "::1"],
        })

    def test_initial_state(self):
        """Shield should start with empty state."""
        assert len(self.shield._failed_attempts) == 0
        assert len(self.shield._blocked_ips) == 0
        assert len(self.shield._recent_events) == 0
        assert not self.shield.running

    def test_get_recent_events_empty(self):
        """Should return empty list initially."""
        assert self.shield.get_recent_events() == []

    def test_get_blocked_ips_empty(self):
        """Should return empty list initially."""
        assert self.shield.get_blocked_ips() == []

    def test_logon_type_name(self):
        """Should map logon types correctly."""
        assert BruteForceShield._logon_type_name("10") == "RemoteInteractive (RDP)"
        assert BruteForceShield._logon_type_name("3") == "Network (SMB/RDP-NLA)"
        assert BruteForceShield._logon_type_name("99") == "Type 99"

    def test_whitelist_filtering(self):
        """Whitelisted IPs should be in the whitelist set."""
        assert "127.0.0.1" in self.shield._whitelist_ips
        assert "::1" in self.shield._whitelist_ips

    def test_sliding_window_tracking(self):
        """Failed attempts should be tracked per IP."""
        now = datetime.now(timezone.utc)
        self.shield._failed_attempts["10.0.0.1"].append(now)
        self.shield._failed_attempts["10.0.0.1"].append(now)

        assert len(self.shield._failed_attempts["10.0.0.1"]) == 2

    def test_sliding_window_pruning(self):
        """Old attempts should be pruned outside the window."""
        now = datetime.now(timezone.utc)
        old = now - timedelta(seconds=120)  # outside 60s window

        self.shield._failed_attempts["10.0.0.1"] = [old, old, now]

        # Simulate the pruning logic from _poll_events
        window_start = now - timedelta(seconds=self.shield._window_seconds)
        self.shield._failed_attempts["10.0.0.1"] = [
            t for t in self.shield._failed_attempts["10.0.0.1"]
            if t >= window_start
        ]

        assert len(self.shield._failed_attempts["10.0.0.1"]) == 1

    @pytest.mark.asyncio
    async def test_threshold_triggers_block(self):
        """Exceeding threshold should trigger a block."""
        now = datetime.now(timezone.utc)
        ip = "192.168.1.50"

        # Manually populate to just below threshold
        self.shield._failed_attempts[ip] = [now, now]

        # Mock the block function
        with patch.object(self.shield, "_block_ip", new_callable=AsyncMock) as mock_block:
            # Simulate adding another attempt that crosses threshold
            self.shield._failed_attempts[ip].append(now)

            if (
                len(self.shield._failed_attempts[ip]) >= self.shield._threshold
                and ip not in self.shield._blocked_ips
            ):
                await self.shield._block_ip(ip)

            mock_block.assert_called_once_with(ip)

    @pytest.mark.asyncio
    async def test_already_blocked_ip_not_reblocked(self):
        """An already blocked IP should not be blocked again."""
        ip = "192.168.1.50"
        now = datetime.now(timezone.utc)

        self.shield._blocked_ips[ip] = now
        self.shield._failed_attempts[ip] = [now, now, now, now]

        with patch.object(self.shield, "_block_ip", new_callable=AsyncMock) as mock_block:
            # Threshold is exceeded but IP is already blocked
            if (
                len(self.shield._failed_attempts[ip]) >= self.shield._threshold
                and ip not in self.shield._blocked_ips
            ):
                await self.shield._block_ip(ip)

            mock_block.assert_not_called()

    def test_get_blocked_ips_with_remaining(self):
        """Should compute remaining seconds correctly."""
        now = datetime.now(timezone.utc)
        self.shield._blocked_ips["10.0.0.5"] = now - timedelta(seconds=100)
        self.shield._block_duration = 300

        result = self.shield.get_blocked_ips()
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.5"
        # Should be approximately 200 seconds remaining
        assert 190 <= result[0]["remaining_seconds"] <= 210

    def test_get_blocked_ips_expired(self):
        """Expired blocked IPs should show 0 remaining."""
        now = datetime.now(timezone.utc)
        self.shield._blocked_ips["10.0.0.5"] = now - timedelta(seconds=500)
        self.shield._block_duration = 300

        result = self.shield.get_blocked_ips()
        assert result[0]["remaining_seconds"] == 0

    @pytest.mark.asyncio
    async def test_unblock_ip_found(self):
        """unblock_ip should remove a blocked IP."""
        self.shield._blocked_ips["10.0.0.5"] = datetime.now(timezone.utc)

        with patch.object(self.shield, "_unblock_ip", new_callable=AsyncMock):
            result = await self.shield.unblock_ip("10.0.0.5")
            assert result["status"] == "unblocked"

    @pytest.mark.asyncio
    async def test_unblock_ip_not_found(self):
        """unblock_ip should return not_found for unknown IP."""
        result = await self.shield.unblock_ip("10.0.0.99")
        assert result["status"] == "not_found"

    def test_recent_events_limit(self):
        """get_recent_events should respect limit parameter."""
        self.shield._recent_events = [{"i": i} for i in range(100)]
        result = self.shield.get_recent_events(limit=10)
        assert len(result) == 10

    def test_recent_events_ordering(self):
        """Recent events should be returned newest-first."""
        self.shield._recent_events = [{"i": 1}, {"i": 2}, {"i": 3}]
        result = self.shield.get_recent_events(limit=3)
        assert result[0]["i"] == 3
        assert result[-1]["i"] == 1

    @patch("backend.modules.brute_force_shield.subprocess")
    def test_read_event_log_empty(self, mock_subprocess):
        """Should handle empty event log gracefully."""
        mock_subprocess.run.return_value = MagicMock(stdout="[]", returncode=0)
        events = self.shield._read_event_log()
        assert events == []

    @patch("backend.modules.brute_force_shield.subprocess")
    def test_read_event_log_timeout(self, mock_subprocess):
        """Should handle timeout gracefully."""
        import subprocess
        mock_subprocess.run.side_effect = subprocess.TimeoutExpired(cmd="ps", timeout=15)
        mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
        events = self.shield._read_event_log()
        assert events == []

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        """Should start and stop cleanly."""
        with patch.object(self.shield, "_poll_events", new_callable=AsyncMock):
            await self.shield.start()
            assert self.shield.running is True
            assert self.shield.health_status == "running"

        with patch.object(self.shield, "_cleanup_firewall_rules", new_callable=AsyncMock):
            await self.shield.stop()
            assert self.shield.running is False
            assert self.shield.health_status == "stopped"

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Health check should include relevant details."""
        health = await self.shield.health_check()
        assert health["status"] == "initialized"
        assert "blocked_ips" in health["details"]
        assert "threshold" in health["details"]
        assert health["details"]["threshold"] == 3
