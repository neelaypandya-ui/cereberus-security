"""DNS/IP/IPv6 Leak Detection for VPN connections.

Checks for various types of leaks that could expose the user's real IP
or DNS queries outside the VPN tunnel.
"""

import asyncio
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional

import httpx

from ..utils.logging import get_logger

logger = get_logger("vpn.leak_checker")


@dataclass
class LeakCheckResult:
    """Results from a leak check."""
    dns_leak: bool = False
    ip_leak: bool = False
    ipv6_leak: bool = False
    details: dict = field(default_factory=dict)
    dns_servers_found: list[str] = field(default_factory=list)
    visible_ip: Optional[str] = None
    ipv6_addresses: list[str] = field(default_factory=list)
    timestamp: Optional[str] = None

    @property
    def has_leak(self) -> bool:
        return self.dns_leak or self.ip_leak or self.ipv6_leak

    def to_dict(self) -> dict:
        return {
            "dns_leak": self.dns_leak,
            "ip_leak": self.ip_leak,
            "ipv6_leak": self.ipv6_leak,
            "has_leak": self.has_leak,
            "dns_servers_found": self.dns_servers_found,
            "visible_ip": self.visible_ip,
            "ipv6_addresses": self.ipv6_addresses,
            "details": self.details,
        }


class LeakChecker:
    """Checks for DNS, IP, and IPv6 leaks when VPN is active."""

    def __init__(self, trusted_dns: list[str] | None = None):
        self._trusted_dns = trusted_dns or []
        self._check_interval = 60  # seconds
        self._monitoring = False

    async def check_ip_leak(self, expected_vpn_ip: Optional[str] = None) -> dict:
        """Check if visible IP matches expected VPN IP.

        Queries external services to determine visible public IP.
        """
        result = {"leak": False, "visible_ip": None, "error": None}

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                # Try multiple services for reliability
                services = [
                    "https://api.ipify.org?format=json",
                    "https://httpbin.org/ip",
                ]
                for service in services:
                    try:
                        resp = await client.get(service)
                        if resp.status_code == 200:
                            data = resp.json()
                            visible_ip = data.get("ip") or data.get("origin", "").split(",")[0].strip()
                            result["visible_ip"] = visible_ip

                            if expected_vpn_ip and visible_ip != expected_vpn_ip:
                                result["leak"] = True
                                logger.warning(
                                    "ip_leak_detected",
                                    visible_ip=visible_ip,
                                    expected_ip=expected_vpn_ip,
                                )
                            break
                    except Exception:
                        continue
        except Exception as e:
            result["error"] = str(e)
            logger.error("ip_leak_check_failed", error=str(e))

        return result

    async def check_dns_leak(self) -> dict:
        """Check for DNS leaks by examining configured DNS servers.

        Compares active DNS servers against trusted VPN DNS servers.
        """
        result = {"leak": False, "dns_servers": [], "error": None}

        try:
            # Get DNS servers from ipconfig
            proc = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            # Extract DNS server lines
            dns_servers = []
            lines = proc.stdout.split("\n")
            in_dns_section = False
            for line in lines:
                if "DNS Servers" in line:
                    in_dns_section = True
                    # Extract IP from this line
                    parts = line.split(":")
                    if len(parts) > 1:
                        ip = parts[-1].strip()
                        if ip:
                            dns_servers.append(ip)
                elif in_dns_section:
                    stripped = line.strip()
                    # Check if it's a continuation IP
                    if re.match(r"^\d+\.\d+\.\d+\.\d+", stripped):
                        dns_servers.append(stripped)
                    elif re.match(r"^[0-9a-fA-F:]+", stripped) and ":" in stripped:
                        dns_servers.append(stripped)
                    else:
                        in_dns_section = False

            result["dns_servers"] = dns_servers

            # Check against trusted DNS
            if self._trusted_dns:
                for server in dns_servers:
                    if server not in self._trusted_dns:
                        result["leak"] = True
                        logger.warning(
                            "dns_leak_detected",
                            untrusted_dns=server,
                            trusted_dns=self._trusted_dns,
                        )

        except Exception as e:
            result["error"] = str(e)
            logger.error("dns_leak_check_failed", error=str(e))

        return result

    async def check_ipv6_leak(self) -> dict:
        """Check for IPv6 leaks that bypass the VPN tunnel.

        Many VPNs only tunnel IPv4 traffic, leaving IPv6 exposed.
        """
        result = {"leak": False, "ipv6_addresses": [], "error": None}

        try:
            proc = subprocess.run(
                ["netsh", "interface", "ipv6", "show", "addresses"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            # Parse IPv6 addresses
            ipv6_addrs = []
            for line in proc.stdout.split("\n"):
                line = line.strip()
                # Look for global IPv6 addresses (not link-local fe80::)
                match = re.search(r"(?:Address\s+)?([0-9a-fA-F:]{3,}(?:::[0-9a-fA-F]+)+)", line)
                if match:
                    addr = match.group(1)
                    if not addr.startswith("fe80") and not addr.startswith("::1"):
                        ipv6_addrs.append(addr)

            result["ipv6_addresses"] = ipv6_addrs

            if ipv6_addrs:
                result["leak"] = True
                logger.warning("ipv6_leak_detected", addresses=ipv6_addrs)

        except Exception as e:
            result["error"] = str(e)
            logger.error("ipv6_leak_check_failed", error=str(e))

        return result

    async def remediate_dns(self, interface_name: str, dns_servers: list[str]) -> bool:
        """Force DNS servers on an interface to prevent DNS leaks.

        Args:
            interface_name: Network interface to configure.
            dns_servers: List of DNS server IPs to set.
        """
        if not dns_servers:
            return False

        try:
            # Set primary DNS
            subprocess.run(
                [
                    "netsh", "interface", "ip", "set", "dns",
                    f"name={interface_name}",
                    "source=static",
                    f"addr={dns_servers[0]}",
                ],
                capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            # Set secondary DNS if provided
            if len(dns_servers) > 1:
                subprocess.run(
                    [
                        "netsh", "interface", "ip", "add", "dns",
                        f"name={interface_name}",
                        f"addr={dns_servers[1]}",
                        "index=2",
                    ],
                    capture_output=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )

            logger.info("dns_remediation_applied", interface=interface_name, dns=dns_servers)
            return True
        except Exception as e:
            logger.error("dns_remediation_failed", error=str(e))
            return False

    async def run_full_check(self, expected_vpn_ip: Optional[str] = None) -> LeakCheckResult:
        """Run all leak checks and return combined result."""
        ip_result, dns_result, ipv6_result = await asyncio.gather(
            self.check_ip_leak(expected_vpn_ip),
            self.check_dns_leak(),
            self.check_ipv6_leak(),
        )

        from datetime import datetime, timezone
        result = LeakCheckResult(
            ip_leak=ip_result.get("leak", False),
            dns_leak=dns_result.get("leak", False),
            ipv6_leak=ipv6_result.get("leak", False),
            visible_ip=ip_result.get("visible_ip"),
            dns_servers_found=dns_result.get("dns_servers", []),
            ipv6_addresses=ipv6_result.get("ipv6_addresses", []),
            details={
                "ip_check": ip_result,
                "dns_check": dns_result,
                "ipv6_check": ipv6_result,
            },
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        if result.has_leak:
            logger.warning(
                "leak_check_detected_issues",
                ip_leak=result.ip_leak,
                dns_leak=result.dns_leak,
                ipv6_leak=result.ipv6_leak,
            )

        return result

    async def start_monitoring(
        self,
        expected_vpn_ip: Optional[str] = None,
        on_leak=None,
        interval: int = 60,
    ) -> None:
        """Start periodic leak checking.

        Args:
            expected_vpn_ip: Expected VPN IP for IP leak detection.
            on_leak: Async callback called with LeakCheckResult when leak is found.
            interval: Check interval in seconds.
        """
        self._monitoring = True
        self._check_interval = interval
        logger.info("leak_monitoring_started", interval=interval)

        while self._monitoring:
            result = await self.run_full_check(expected_vpn_ip)
            if result.has_leak and on_leak:
                await on_leak(result)
            await asyncio.sleep(self._check_interval)

    def stop_monitoring(self) -> None:
        """Stop the monitoring loop."""
        self._monitoring = False
        logger.info("leak_monitoring_stopped")
