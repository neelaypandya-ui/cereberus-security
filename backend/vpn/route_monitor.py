"""Windows routing table monitor.

Parses `route print` output to understand routing topology,
detect split-tunneling, and monitor for unauthorized route changes.
"""

import asyncio
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..utils.logging import get_logger

logger = get_logger("vpn.route_monitor")


@dataclass
class Route:
    """A single routing table entry."""
    destination: str
    netmask: str
    gateway: str
    interface: str
    metric: int

    @property
    def is_default(self) -> bool:
        return self.destination == "0.0.0.0" and self.netmask == "0.0.0.0"


@dataclass
class RoutingSnapshot:
    """Snapshot of the routing table at a point in time."""
    timestamp: datetime
    routes: list[Route] = field(default_factory=list)
    default_routes: list[Route] = field(default_factory=list)
    vpn_routes: list[Route] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_routes": len(self.routes),
            "default_routes": len(self.default_routes),
            "vpn_routes": len(self.vpn_routes),
        }


class RouteMonitor:
    """Monitors the Windows routing table for changes and split-tunneling."""

    def __init__(self, vpn_interface: Optional[str] = None):
        self._vpn_interface = vpn_interface
        self._last_snapshot: Optional[RoutingSnapshot] = None
        self._monitoring = False
        self._poll_interval = 2.0  # seconds

    def parse_route_table(self) -> list[Route]:
        """Parse `route print` output into Route objects."""
        routes = []
        try:
            result = subprocess.run(
                ["route", "print", "-4"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            in_routes = False
            for line in result.stdout.split("\n"):
                line = line.strip()

                # Detect the start of the IPv4 route table
                if "Network Destination" in line:
                    in_routes = True
                    continue

                if in_routes:
                    if not line or "=" in line:
                        in_routes = False
                        continue

                    # Parse route line: dest netmask gateway interface metric
                    parts = line.split()
                    if len(parts) >= 5:
                        try:
                            route = Route(
                                destination=parts[0],
                                netmask=parts[1],
                                gateway=parts[2],
                                interface=parts[3],
                                metric=int(parts[4]) if parts[4].isdigit() else 0,
                            )
                            routes.append(route)
                        except (ValueError, IndexError):
                            continue

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("route_print_failed", error=str(e))

        return routes

    def take_snapshot(self) -> RoutingSnapshot:
        """Take a snapshot of the current routing table."""
        routes = self.parse_route_table()

        default_routes = [r for r in routes if r.is_default]
        vpn_routes = []

        if self._vpn_interface:
            vpn_routes = [
                r for r in routes
                if self._vpn_interface in r.interface or self._vpn_interface in r.gateway
            ]

        snapshot = RoutingSnapshot(
            timestamp=datetime.now(timezone.utc),
            routes=routes,
            default_routes=default_routes,
            vpn_routes=vpn_routes,
        )

        return snapshot

    def detect_split_tunnel(self, snapshot: RoutingSnapshot) -> dict:
        """Detect split-tunneling configuration.

        Split-tunneling means some routes go through VPN and some don't.
        """
        result = {
            "split_tunnel_detected": False,
            "vpn_default_route": False,
            "physical_default_route": False,
            "non_vpn_routes": [],
        }

        if not self._vpn_interface:
            return result

        for route in snapshot.default_routes:
            if self._vpn_interface in route.interface:
                result["vpn_default_route"] = True
            else:
                result["physical_default_route"] = True

        # If both VPN and physical have default routes, split tunnel might be active
        if result["vpn_default_route"] and result["physical_default_route"]:
            result["split_tunnel_detected"] = True

        # Find routes that explicitly bypass VPN
        for route in snapshot.routes:
            if not route.is_default and self._vpn_interface not in route.interface:
                # This route goes through non-VPN interface
                if route.destination not in ("127.0.0.0", "224.0.0.0", "255.255.255.255"):
                    result["non_vpn_routes"].append({
                        "destination": route.destination,
                        "gateway": route.gateway,
                        "interface": route.interface,
                    })

        return result

    def detect_changes(self, old: RoutingSnapshot, new: RoutingSnapshot) -> list[dict]:
        """Compare two snapshots and return a list of changes."""
        changes = []

        old_set = {(r.destination, r.netmask, r.gateway) for r in old.routes}
        new_set = {(r.destination, r.netmask, r.gateway) for r in new.routes}

        # Added routes
        for route_key in new_set - old_set:
            changes.append({
                "type": "route_added",
                "destination": route_key[0],
                "netmask": route_key[1],
                "gateway": route_key[2],
            })

        # Removed routes
        for route_key in old_set - new_set:
            changes.append({
                "type": "route_removed",
                "destination": route_key[0],
                "netmask": route_key[1],
                "gateway": route_key[2],
            })

        return changes

    def set_vpn_interface(self, interface: str) -> None:
        """Update the known VPN interface for monitoring."""
        self._vpn_interface = interface
        logger.info("vpn_interface_set", interface=interface)

    async def start_monitoring(self, on_change=None) -> None:
        """Start continuous route monitoring.

        Args:
            on_change: Async callback called with list of change dicts.
        """
        self._monitoring = True
        self._last_snapshot = self.take_snapshot()
        logger.info("route_monitoring_started", poll_interval=self._poll_interval)

        while self._monitoring:
            await asyncio.sleep(self._poll_interval)

            new_snapshot = self.take_snapshot()

            if self._last_snapshot:
                changes = self.detect_changes(self._last_snapshot, new_snapshot)
                if changes:
                    logger.info("route_changes_detected", count=len(changes))
                    if on_change:
                        await on_change(changes)

            self._last_snapshot = new_snapshot

    def stop_monitoring(self) -> None:
        """Stop the monitoring loop."""
        self._monitoring = False
        logger.info("route_monitoring_stopped")
