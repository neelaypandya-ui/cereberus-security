"""VPN Detection & Interface Management for Windows.

Detects active VPN connections by inspecting network adapters, processes,
and interface configurations on Windows.
"""

import asyncio
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import psutil

from ..utils.logging import get_logger

logger = get_logger("vpn.detector")

# Known VPN adapter name patterns on Windows
VPN_ADAPTER_PATTERNS = [
    r"TAP-Windows",
    r"TAP-Win32",
    r"WireGuard Tunnel",
    r"NordLynx",
    r"Wintun",
    r"Windscribe",
    r"OpenVPN",
    r"ProtonVPN",
    r"ExpressVPN",
    r"Surfshark",
    r"CyberGhost",
    r"Private Internet Access",
    r"PIA",
    r"Mullvad",
    r"IVPN",
    r"Hotspot Shield",
    r"TunnelBear",
    r"VPN",
]

# Known VPN process names
VPN_PROCESSES = [
    "openvpn.exe",
    "wireguard.exe",
    "nordvpn.exe",
    "nordlynx.exe",
    "expressvpn.exe",
    "surfshark.exe",
    "windscribe.exe",
    "protonvpn.exe",
    "cyberghost.exe",
    "pia-client.exe",
    "mullvad-daemon.exe",
    "ivpn-svc.exe",
]

# Protocol detection from adapter type
PROTOCOL_HINTS = {
    "TAP": "OpenVPN",
    "Wintun": "WireGuard",
    "WireGuard": "WireGuard",
    "NordLynx": "WireGuard/NordLynx",
    "L2TP": "L2TP/IPsec",
    "SSTP": "SSTP",
    "IKEv2": "IKEv2",
    "PPTP": "PPTP",
}


@dataclass
class VPNState:
    """Current state of VPN connection."""
    connected: bool = False
    protocol: Optional[str] = None
    provider: Optional[str] = None
    vpn_ip: Optional[str] = None
    real_ip: Optional[str] = None
    interface_name: Optional[str] = None
    server_location: Optional[str] = None
    connected_since: Optional[datetime] = None
    adapter_details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "connected": self.connected,
            "protocol": self.protocol,
            "provider": self.provider,
            "vpn_ip": self.vpn_ip,
            "real_ip": self.real_ip,
            "interface_name": self.interface_name,
            "server_location": self.server_location,
            "connected_since": self.connected_since.isoformat() if self.connected_since else None,
        }


class VPNDetector:
    """Detects and monitors VPN connections on Windows."""

    def __init__(self, trusted_interfaces: list[str] | None = None):
        self._trusted_interfaces = trusted_interfaces or []
        self._current_state = VPNState()
        self._previous_state = VPNState()
        self._monitoring = False
        self._poll_interval = 0.5  # 500ms

    @property
    def state(self) -> VPNState:
        return self._current_state

    def detect_vpn_adapters(self) -> list[dict]:
        """Detect VPN network adapters using psutil and name pattern matching."""
        vpn_adapters = []
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for iface_name, addrs in interfaces.items():
            # Check if name matches any VPN pattern
            is_vpn = any(
                re.search(pattern, iface_name, re.IGNORECASE)
                for pattern in VPN_ADAPTER_PATTERNS
            )

            # Skip trusted/whitelisted interfaces
            if iface_name in self._trusted_interfaces:
                continue

            if is_vpn:
                iface_stat = stats.get(iface_name)
                is_up = iface_stat.isup if iface_stat else False

                # Extract IP addresses
                ipv4 = None
                ipv6 = None
                for addr in addrs:
                    if addr.family.name == "AF_INET":
                        ipv4 = addr.address
                    elif addr.family.name == "AF_INET6":
                        ipv6 = addr.address

                adapter_info = {
                    "name": iface_name,
                    "is_up": is_up,
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "speed": iface_stat.speed if iface_stat else 0,
                    "mtu": iface_stat.mtu if iface_stat else 0,
                }
                vpn_adapters.append(adapter_info)

        return vpn_adapters

    def detect_vpn_processes(self) -> list[dict]:
        """Detect running VPN client processes."""
        found = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pname = proc.info["name"].lower() if proc.info["name"] else ""
                if pname in VPN_PROCESSES:
                    found.append({
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "exe": proc.info["exe"],
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return found

    def _detect_protocol(self, adapter_name: str, processes: list[dict]) -> Optional[str]:
        """Infer VPN protocol from adapter name and running processes."""
        for hint_key, protocol in PROTOCOL_HINTS.items():
            if hint_key.lower() in adapter_name.lower():
                return protocol

        # Fallback: check processes
        proc_names = [p["name"].lower() for p in processes]
        if any("openvpn" in n for n in proc_names):
            return "OpenVPN"
        if any("wireguard" in n for n in proc_names):
            return "WireGuard"
        return None

    def _detect_provider(self, adapter_name: str, processes: list[dict]) -> Optional[str]:
        """Infer VPN provider from adapter name and processes."""
        providers = {
            "nord": "NordVPN",
            "express": "ExpressVPN",
            "surfshark": "Surfshark",
            "windscribe": "Windscribe",
            "proton": "ProtonVPN",
            "cyberghost": "CyberGhost",
            "mullvad": "Mullvad",
            "ivpn": "IVPN",
            "pia": "Private Internet Access",
            "private internet": "Private Internet Access",
            "tunnelbear": "TunnelBear",
            "hotspot": "Hotspot Shield",
        }

        # Check adapter name
        for key, provider in providers.items():
            if key in adapter_name.lower():
                return provider

        # Check process names
        for proc in processes:
            pname = proc["name"].lower()
            for key, provider in providers.items():
                if key in pname:
                    return provider

        return None

    def _get_ipconfig_details(self) -> str:
        """Run ipconfig /all and return output."""
        try:
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def _get_netsh_interfaces(self) -> str:
        """Run netsh interface show interface and return output."""
        try:
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def _get_wmi_adapters(self) -> list[dict]:
        """Query WMI for network adapter details."""
        adapters = []
        try:
            import wmi
            c = wmi.WMI()
            for adapter in c.Win32_NetworkAdapter(NetConnectionStatus=2):
                adapters.append({
                    "name": adapter.Name,
                    "adapter_type": adapter.AdapterType,
                    "mac": adapter.MACAddress,
                    "manufacturer": adapter.Manufacturer,
                    "net_connection_id": adapter.NetConnectionID,
                })
        except Exception as e:
            logger.warning("wmi_query_failed", error=str(e))
        return adapters

    async def detect(self) -> VPNState:
        """Run full VPN detection and return current state."""
        adapters = self.detect_vpn_adapters()
        processes = self.detect_vpn_processes()

        # Find active VPN adapter
        active_adapter = None
        for adapter in adapters:
            if adapter["is_up"] and adapter["ipv4"]:
                active_adapter = adapter
                break

        if active_adapter:
            protocol = self._detect_protocol(active_adapter["name"], processes)
            provider = self._detect_provider(active_adapter["name"], processes)

            self._current_state = VPNState(
                connected=True,
                protocol=protocol,
                provider=provider,
                vpn_ip=active_adapter["ipv4"],
                interface_name=active_adapter["name"],
                connected_since=(
                    self._current_state.connected_since
                    if self._current_state.connected
                    else datetime.now(timezone.utc)
                ),
                adapter_details=active_adapter,
            )
        else:
            self._current_state = VPNState(connected=False)

        logger.debug(
            "vpn_detection_complete",
            connected=self._current_state.connected,
            interface=self._current_state.interface_name,
            protocol=self._current_state.protocol,
            provider=self._current_state.provider,
        )

        return self._current_state

    def state_changed(self) -> bool:
        """Check if state changed since last detection."""
        return self._current_state.connected != self._previous_state.connected

    async def start_monitoring(self, on_change=None) -> None:
        """Start continuous VPN monitoring loop.

        Args:
            on_change: Async callback called with (new_state, old_state) on changes.
        """
        self._monitoring = True
        logger.info("vpn_monitoring_started", poll_interval=self._poll_interval)

        while self._monitoring:
            self._previous_state = VPNState(
                connected=self._current_state.connected,
                interface_name=self._current_state.interface_name,
            )

            await self.detect()

            if self.state_changed() and on_change:
                await on_change(self._current_state, self._previous_state)

            await asyncio.sleep(self._poll_interval)

    def stop_monitoring(self) -> None:
        """Stop the monitoring loop."""
        self._monitoring = False
        logger.info("vpn_monitoring_stopped")
