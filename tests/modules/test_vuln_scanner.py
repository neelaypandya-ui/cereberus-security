"""Tests for the Vulnerability Scanner module."""

from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from backend.modules.vuln_scanner import VulnScanner


class TestVulnScanner:
    @pytest.fixture
    def scanner(self):
        return VulnScanner(config={
            "scan_interval": 3600,
            "check_windows_updates": False,
            "check_open_ports": True,
            "check_weak_configs": False,
            "check_software": False,
        })

    @pytest.fixture
    def full_scanner(self):
        return VulnScanner(config={
            "scan_interval": 3600,
            "check_windows_updates": True,
            "check_open_ports": True,
            "check_weak_configs": True,
            "check_software": True,
        })

    def test_probe_port_closed(self, scanner):
        # Port 19999 should not be open on localhost
        assert scanner._probe_port(19999) is False

    @pytest.mark.asyncio
    async def test_check_open_ports_none_open(self, scanner):
        with patch.object(scanner, "_probe_port", return_value=False):
            vulns = await scanner._check_open_ports()
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_check_open_ports_rdp_open(self, scanner):
        def mock_probe(port, host="127.0.0.1", timeout=1.0):
            return port == 3389

        with patch.object(scanner, "_probe_port", side_effect=mock_probe):
            vulns = await scanner._check_open_ports()

        assert len(vulns) == 1
        assert vulns[0]["service"] == "RDP"
        assert vulns[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_check_open_ports_telnet_critical(self, scanner):
        def mock_probe(port, host="127.0.0.1", timeout=1.0):
            return port == 23

        with patch.object(scanner, "_probe_port", side_effect=mock_probe):
            vulns = await scanner._check_open_ports()

        assert len(vulns) == 1
        assert vulns[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_run_scan(self, scanner):
        with patch.object(scanner, "_probe_port", return_value=False):
            report = await scanner.run_scan()

        assert "total_findings" in report
        assert "vulnerabilities" in report

    @pytest.mark.asyncio
    async def test_run_scan_with_findings(self, scanner):
        def mock_probe(port, host="127.0.0.1", timeout=1.0):
            return port in (23, 445)

        with patch.object(scanner, "_probe_port", side_effect=mock_probe):
            report = await scanner.run_scan()

        assert report["total_findings"] == 2
        assert "critical" in report["severity_counts"]

    @pytest.mark.asyncio
    async def test_get_last_report(self, scanner):
        with patch.object(scanner, "_probe_port", return_value=False):
            await scanner.run_scan()

        report = scanner.get_last_report()
        assert report is not None
        assert "scan_time" in report

    @pytest.mark.asyncio
    async def test_health_check(self, scanner):
        health = await scanner.health_check()
        assert health["status"] == "initialized"
        assert "details" in health

    @pytest.mark.asyncio
    async def test_weak_config_check_timeout(self, full_scanner):
        """Weak config checks should handle timeout gracefully."""
        with patch("asyncio.create_subprocess_shell", side_effect=FileNotFoundError):
            vulns = await full_scanner._check_weak_configurations()
        # Should not crash, just return empty
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_windows_update_check_timeout(self, full_scanner):
        """Windows update check should handle timeout gracefully."""
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            vulns = await full_scanner._check_windows_updates()
        assert isinstance(vulns, list)
