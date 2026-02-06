"""Tests for VPN leak checker module."""

from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from backend.vpn.leak_checker import LeakChecker, LeakCheckResult


class TestLeakChecker:
    def setup_method(self):
        self.checker = LeakChecker(trusted_dns=["10.8.0.1"])

    def test_initial_state(self):
        """Leak checker should initialize with trusted DNS."""
        assert self.checker._trusted_dns == ["10.8.0.1"]

    def test_leak_check_result_no_leak(self):
        """LeakCheckResult with no leaks should report no leak."""
        result = LeakCheckResult()
        assert result.has_leak is False

    def test_leak_check_result_with_leak(self):
        """LeakCheckResult with any leak should report has_leak."""
        result = LeakCheckResult(dns_leak=True)
        assert result.has_leak is True

        result = LeakCheckResult(ip_leak=True)
        assert result.has_leak is True

        result = LeakCheckResult(ipv6_leak=True)
        assert result.has_leak is True

    def test_leak_check_result_to_dict(self):
        """Should serialize to dict correctly."""
        result = LeakCheckResult(
            dns_leak=True,
            dns_servers_found=["8.8.8.8"],
            visible_ip="1.2.3.4",
        )
        d = result.to_dict()
        assert d["dns_leak"] is True
        assert d["has_leak"] is True
        assert "8.8.8.8" in d["dns_servers_found"]

    @patch("backend.vpn.leak_checker.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_ip_leak_check_no_leak(self, mock_client_class):
        """Should detect no IP leak when visible IP matches VPN IP."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ip": "10.8.0.2"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_class.return_value = mock_client

        result = await self.checker.check_ip_leak(expected_vpn_ip="10.8.0.2")
        assert result["leak"] is False
        assert result["visible_ip"] == "10.8.0.2"

    @patch("backend.vpn.leak_checker.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_ip_leak_check_with_leak(self, mock_client_class):
        """Should detect IP leak when visible IP doesn't match VPN IP."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ip": "203.0.113.5"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_class.return_value = mock_client

        result = await self.checker.check_ip_leak(expected_vpn_ip="10.8.0.2")
        assert result["leak"] is True
        assert result["visible_ip"] == "203.0.113.5"

    @patch("backend.vpn.leak_checker.subprocess")
    @pytest.mark.asyncio
    async def test_dns_leak_check_no_leak(self, mock_subprocess, mock_subprocess_ipconfig):
        """Should detect no DNS leak when DNS matches trusted servers."""
        # Use ipconfig output with VPN DNS (10.8.0.1)
        mock_subprocess.run.return_value = MagicMock(
            stdout=mock_subprocess_ipconfig,
            returncode=0,
        )
        mock_subprocess.CREATE_NO_WINDOW = 0x08000000

        # Checker trusts 10.8.0.1 and 8.8.8.8
        checker = LeakChecker(trusted_dns=["10.8.0.1", "8.8.8.8", "8.8.4.4"])
        result = await checker.check_dns_leak()
        assert result["leak"] is False

    @patch("backend.vpn.leak_checker.subprocess")
    @pytest.mark.asyncio
    async def test_dns_leak_check_with_leak(self, mock_subprocess, mock_subprocess_ipconfig):
        """Should detect DNS leak when DNS doesn't match trusted servers."""
        mock_subprocess.run.return_value = MagicMock(
            stdout=mock_subprocess_ipconfig,
            returncode=0,
        )
        mock_subprocess.CREATE_NO_WINDOW = 0x08000000

        # Only trust 10.8.0.1 — 8.8.8.8 should be flagged
        checker = LeakChecker(trusted_dns=["10.8.0.1"])
        result = await checker.check_dns_leak()
        assert result["leak"] is True

    @patch("backend.vpn.leak_checker.subprocess")
    @pytest.mark.asyncio
    async def test_ipv6_leak_check_no_leak(self, mock_subprocess):
        """Should detect no IPv6 leak when no global IPv6 addresses exist."""
        mock_subprocess.run.return_value = MagicMock(
            stdout="No addresses found.\n",
            returncode=0,
        )
        mock_subprocess.CREATE_NO_WINDOW = 0x08000000

        result = await self.checker.check_ipv6_leak()
        assert result["leak"] is False

    @pytest.mark.asyncio
    async def test_run_full_check(self):
        """Full check should combine all sub-checks."""
        with patch.object(self.checker, "check_ip_leak", new_callable=AsyncMock) as mock_ip, \
             patch.object(self.checker, "check_dns_leak", new_callable=AsyncMock) as mock_dns, \
             patch.object(self.checker, "check_ipv6_leak", new_callable=AsyncMock) as mock_ipv6:

            mock_ip.return_value = {"leak": False, "visible_ip": "10.8.0.2", "error": None}
            mock_dns.return_value = {"leak": False, "dns_servers": ["10.8.0.1"], "error": None}
            mock_ipv6.return_value = {"leak": False, "ipv6_addresses": [], "error": None}

            result = await self.checker.run_full_check(expected_vpn_ip="10.8.0.2")
            assert result.has_leak is False
            assert result.visible_ip == "10.8.0.2"
