"""Tests for VPN detector module."""

from unittest.mock import MagicMock, patch

import pytest

from backend.vpn.detector import VPNDetector, VPNState, VPN_ADAPTER_PATTERNS


class TestVPNDetector:
    def setup_method(self):
        self.detector = VPNDetector(trusted_interfaces=["Loopback"])

    def test_initial_state_disconnected(self):
        """VPN state should start as disconnected."""
        assert self.detector.state.connected is False
        assert self.detector.state.protocol is None
        assert self.detector.state.vpn_ip is None

    @patch("backend.vpn.detector.psutil")
    def test_detect_vpn_adapters(self, mock_psutil, mock_psutil_interfaces):
        """Should detect VPN adapters from network interfaces."""
        mock_addrs, mock_stats = mock_psutil_interfaces
        mock_psutil.net_if_addrs.return_value = mock_addrs
        mock_psutil.net_if_stats.return_value = mock_stats

        adapters = self.detector.detect_vpn_adapters()

        assert len(adapters) == 1
        assert adapters[0]["name"] == "TAP-Windows Adapter V9"
        assert adapters[0]["is_up"] is True
        assert adapters[0]["ipv4"] == "10.8.0.2"

    @patch("backend.vpn.detector.psutil")
    def test_no_vpn_adapters(self, mock_psutil):
        """Should return empty list when no VPN adapters are found."""
        mock_psutil.net_if_addrs.return_value = {
            "Ethernet": [
                MagicMock(family=MagicMock(name="AF_INET"), address="192.168.1.100"),
            ],
        }
        mock_psutil.net_if_stats.return_value = {
            "Ethernet": MagicMock(isup=True, speed=1000, mtu=1500),
        }

        adapters = self.detector.detect_vpn_adapters()
        assert len(adapters) == 0

    @patch("backend.vpn.detector.psutil")
    def test_detect_vpn_processes(self, mock_psutil):
        """Should detect running VPN processes."""
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 1234, "name": "openvpn.exe", "exe": "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe"}
        mock_psutil.process_iter.return_value = [mock_proc]
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.AccessDenied = Exception

        processes = self.detector.detect_vpn_processes()
        assert len(processes) == 1
        assert processes[0]["name"] == "openvpn.exe"

    def test_detect_protocol_from_adapter_name(self):
        """Should infer protocol from adapter name."""
        assert self.detector._detect_protocol("TAP-Windows Adapter V9", []) == "OpenVPN"
        assert self.detector._detect_protocol("WireGuard Tunnel", []) == "WireGuard"
        assert self.detector._detect_protocol("NordLynx", []) == "WireGuard/NordLynx"

    def test_detect_provider_from_adapter_name(self):
        """Should infer provider from adapter name."""
        assert self.detector._detect_provider("NordLynx", []) == "NordVPN"
        assert self.detector._detect_provider("Windscribe VPN", []) == "Windscribe"

    def test_detect_provider_from_processes(self):
        """Should infer provider from running processes."""
        procs = [{"name": "expressvpn.exe", "pid": 100, "exe": ""}]
        assert self.detector._detect_provider("Unknown Adapter", procs) == "ExpressVPN"

    @patch("backend.vpn.detector.psutil")
    @pytest.mark.asyncio
    async def test_detect_connected(self, mock_psutil, mock_psutil_interfaces):
        """Full detection should identify active VPN connection."""
        mock_addrs, mock_stats = mock_psutil_interfaces
        mock_psutil.net_if_addrs.return_value = mock_addrs
        mock_psutil.net_if_stats.return_value = mock_stats
        mock_psutil.process_iter.return_value = []
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.AccessDenied = Exception

        state = await self.detector.detect()

        assert state.connected is True
        assert state.vpn_ip == "10.8.0.2"
        assert state.interface_name == "TAP-Windows Adapter V9"
        assert state.protocol == "OpenVPN"

    @patch("backend.vpn.detector.psutil")
    @pytest.mark.asyncio
    async def test_detect_disconnected(self, mock_psutil):
        """Should report disconnected when no VPN adapter is active."""
        mock_psutil.net_if_addrs.return_value = {
            "Ethernet": [
                MagicMock(family=MagicMock(name="AF_INET"), address="192.168.1.100"),
            ],
        }
        mock_psutil.net_if_stats.return_value = {
            "Ethernet": MagicMock(isup=True, speed=1000, mtu=1500),
        }
        mock_psutil.process_iter.return_value = []
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.AccessDenied = Exception

        state = await self.detector.detect()
        assert state.connected is False

    def test_vpn_state_to_dict(self):
        """VPNState.to_dict should produce serializable dict."""
        state = VPNState(connected=True, vpn_ip="10.8.0.2", protocol="OpenVPN")
        d = state.to_dict()
        assert d["connected"] is True
        assert d["vpn_ip"] == "10.8.0.2"
        assert d["protocol"] == "OpenVPN"

    def test_trusted_interfaces_excluded(self):
        """Trusted interfaces should be excluded from VPN detection."""
        detector = VPNDetector(trusted_interfaces=["TAP-Windows Adapter V9"])
        with patch("backend.vpn.detector.psutil") as mock_psutil:
            mock_psutil.net_if_addrs.return_value = {
                "TAP-Windows Adapter V9": [
                    MagicMock(family=MagicMock(name="AF_INET"), address="10.8.0.2"),
                ],
            }
            mock_psutil.net_if_stats.return_value = {
                "TAP-Windows Adapter V9": MagicMock(isup=True, speed=100, mtu=1400),
            }

            adapters = detector.detect_vpn_adapters()
            assert len(adapters) == 0
