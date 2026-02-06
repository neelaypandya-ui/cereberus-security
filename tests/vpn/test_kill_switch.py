"""Tests for VPN kill switch module."""

from unittest.mock import MagicMock, patch, call

import pytest

from backend.vpn.kill_switch import KillSwitch, RULE_PREFIX, LOCAL_SUBNETS


class TestKillSwitch:
    def setup_method(self):
        self.ks = KillSwitch(mode="alert_only")

    def test_initial_state(self):
        """Kill switch should start inactive in alert_only mode."""
        assert self.ks.state.active is False
        assert self.ks.state.mode == "alert_only"

    @pytest.mark.asyncio
    async def test_activate_alert_only(self):
        """Alert-only mode should not create firewall rules."""
        result = await self.ks.activate()
        assert result is True
        assert self.ks.state.active is True
        assert len(self.ks._rules_created) == 0

    @patch("backend.vpn.kill_switch.subprocess")
    @pytest.mark.asyncio
    async def test_activate_full_mode(self, mock_subprocess):
        """Full mode should create firewall block and allow rules."""
        self.ks.set_mode("full")
        mock_subprocess.run.return_value = MagicMock(returncode=0, stdout="Ok.", stderr="")
        mock_subprocess.CREATE_NO_WINDOW = 0x08000000

        result = await self.ks.activate(vpn_server_ip="1.2.3.4")

        assert result is True
        assert self.ks.state.active is True

        # Should have created: local subnet allows + VPN server allow + block all
        expected_rules = len(LOCAL_SUBNETS) + 1 + 1  # locals + vpn server + block all
        assert len(self.ks._rules_created) == expected_rules

    @patch("backend.vpn.kill_switch.subprocess")
    @pytest.mark.asyncio
    async def test_deactivate(self, mock_subprocess):
        """Deactivation should remove all created rules."""
        self.ks.set_mode("full")
        mock_subprocess.run.return_value = MagicMock(returncode=0, stdout="Ok.", stderr="")
        mock_subprocess.CREATE_NO_WINDOW = 0x08000000

        await self.ks.activate()
        rules_count = len(self.ks._rules_created)
        assert rules_count > 0

        await self.ks.deactivate()
        assert self.ks.state.active is False
        assert len(self.ks._rules_created) == 0

    @pytest.mark.asyncio
    async def test_deactivate_when_not_active(self):
        """Deactivating an inactive kill switch should succeed silently."""
        result = await self.ks.deactivate()
        assert result is True

    def test_set_mode_valid(self):
        """Should accept valid modes."""
        self.ks.set_mode("full")
        assert self.ks.state.mode == "full"

        self.ks.set_mode("app_specific")
        assert self.ks.state.mode == "app_specific"

        self.ks.set_mode("alert_only")
        assert self.ks.state.mode == "alert_only"

    def test_set_mode_invalid(self):
        """Should reject invalid modes."""
        with pytest.raises(ValueError):
            self.ks.set_mode("invalid_mode")

    def test_add_blocked_app(self):
        """Should add app to block list without duplicates."""
        self.ks.add_blocked_app("C:\\test\\app.exe")
        self.ks.add_blocked_app("C:\\test\\app.exe")  # duplicate
        assert len(self.ks.state.blocked_apps) == 1

    @patch("backend.vpn.kill_switch.subprocess")
    @pytest.mark.asyncio
    async def test_app_specific_mode(self, mock_subprocess):
        """App-specific mode should block only specified executables."""
        self.ks.set_mode("app_specific")
        self.ks.add_blocked_app("C:\\test\\browser.exe")
        self.ks.add_blocked_app("C:\\test\\email.exe")
        mock_subprocess.run.return_value = MagicMock(returncode=0, stdout="Ok.", stderr="")
        mock_subprocess.CREATE_NO_WINDOW = 0x08000000

        await self.ks.activate()
        assert self.ks.state.active is True
        assert len(self.ks._rules_created) == 2  # One per app

    @patch("backend.vpn.kill_switch.subprocess")
    @pytest.mark.asyncio
    async def test_cleanup(self, mock_subprocess):
        """Emergency cleanup should attempt to remove all known rule patterns."""
        mock_subprocess.run.return_value = MagicMock(returncode=0, stdout="Ok.", stderr="")
        mock_subprocess.CREATE_NO_WINDOW = 0x08000000

        await self.ks.cleanup()
        assert self.ks.state.active is False
        assert len(self.ks._rules_created) == 0

    @patch("backend.vpn.kill_switch.subprocess")
    def test_netsh_failure_handling(self, mock_subprocess):
        """Should handle netsh command failures gracefully."""
        mock_subprocess.run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")
        mock_subprocess.CREATE_NO_WINDOW = 0x08000000

        success, output = self.ks._run_netsh(["advfirewall", "test"])
        assert success is False

    @patch("backend.vpn.kill_switch.subprocess")
    def test_netsh_timeout_handling(self, mock_subprocess):
        """Should handle netsh command timeouts."""
        mock_subprocess.run.side_effect = TimeoutError("timeout")
        mock_subprocess.TimeoutExpired = TimeoutError
        mock_subprocess.CREATE_NO_WINDOW = 0x08000000

        success, output = self.ks._run_netsh(["advfirewall", "test"])
        assert success is False
        assert output == "timeout"
