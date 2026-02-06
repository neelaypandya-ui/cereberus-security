"""Network Sentinel Module — monitors live network connections.

Polls psutil.net_connections() at a configurable interval, caches live connections,
flags suspicious ports, and provides stats for the API/dashboard.
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional

import psutil

from .base_module import BaseModule


# Default suspicious ports associated with backdoors / C2 / common exploit tools
DEFAULT_SUSPICIOUS_PORTS = {
    4444, 5555, 1337, 31337, 6666, 6667, 12345, 27374,
    1234, 3127, 3128, 8080, 9090, 4443, 8443,
}


class NetworkSentinel(BaseModule):
    """Monitors live network connections and flags suspicious activity."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="network_sentinel", config=config)

        cfg = config or {}
        self._poll_interval: int = cfg.get("poll_interval", 5)
        self._suspicious_ports: set[int] = set(
            cfg.get("suspicious_ports", DEFAULT_SUSPICIOUS_PORTS)
        )

        # In-memory caches
        self._connections: list[dict] = []
        self._flagged: list[dict] = []
        self._stats: dict = {}
        self._scan_task: Optional[asyncio.Task] = None
        self._last_scan: Optional[datetime] = None

    async def start(self) -> None:
        """Start the connection monitoring loop."""
        self.running = True
        self.health_status = "running"
        self.logger.info("network_sentinel_starting")

        # Run initial scan
        await self._scan_connections()

        # Start polling loop
        self._scan_task = asyncio.create_task(self._poll_loop())
        self.heartbeat()
        self.logger.info("network_sentinel_started")

    async def stop(self) -> None:
        """Stop the monitoring loop."""
        self.running = False
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        self.health_status = "stopped"
        self.logger.info("network_sentinel_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "total_connections": self._stats.get("total", 0),
                "flagged_count": len(self._flagged),
                "last_scan": self._last_scan.isoformat() if self._last_scan else None,
            },
        }

    async def _poll_loop(self) -> None:
        """Periodically scan connections."""
        while self.running:
            try:
                await asyncio.sleep(self._poll_interval)
                if self.running:
                    await self._scan_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("network_scan_error", error=str(e))
                await asyncio.sleep(self._poll_interval)

    async def _scan_connections(self) -> None:
        """Scan current network connections via psutil."""
        loop = asyncio.get_event_loop()
        raw_conns = await loop.run_in_executor(
            None, lambda: psutil.net_connections(kind="inet")
        )

        connections = []
        flagged = []
        stats = {
            "total": 0,
            "established": 0,
            "listening": 0,
            "time_wait": 0,
            "close_wait": 0,
            "suspicious": 0,
            "tcp": 0,
            "udp": 0,
        }

        for conn in raw_conns:
            entry = self._parse_connection(conn)
            connections.append(entry)

            stats["total"] += 1
            status_lower = entry["status"].lower()
            if status_lower == "established":
                stats["established"] += 1
            elif status_lower == "listen":
                stats["listening"] += 1
            elif status_lower == "time_wait":
                stats["time_wait"] += 1
            elif status_lower == "close_wait":
                stats["close_wait"] += 1

            if entry["protocol"] == "tcp":
                stats["tcp"] += 1
            else:
                stats["udp"] += 1

            if entry["suspicious"]:
                stats["suspicious"] += 1
                flagged.append(entry)

        self._connections = connections
        self._flagged = flagged
        self._stats = stats
        self._last_scan = datetime.now(timezone.utc)
        self.heartbeat()

    def _parse_connection(self, conn) -> dict:
        """Parse a psutil connection into a serializable dict."""
        local_addr = ""
        local_port = None
        remote_addr = ""
        remote_port = None

        if conn.laddr:
            local_addr = conn.laddr.ip if hasattr(conn.laddr, "ip") else str(conn.laddr[0])
            local_port = conn.laddr.port if hasattr(conn.laddr, "port") else conn.laddr[1]

        if conn.raddr:
            remote_addr = conn.raddr.ip if hasattr(conn.raddr, "ip") else str(conn.raddr[0])
            remote_port = conn.raddr.port if hasattr(conn.raddr, "port") else conn.raddr[1]

        proto = "tcp" if conn.type == 1 else "udp"
        status = conn.status if hasattr(conn, "status") else "NONE"

        suspicious = self._is_suspicious(local_port, remote_port)

        return {
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "protocol": proto,
            "status": status,
            "pid": conn.pid,
            "suspicious": suspicious,
        }

    def _is_suspicious(self, local_port: int | None, remote_port: int | None) -> bool:
        """Check if either port is in the suspicious set."""
        if local_port and local_port in self._suspicious_ports:
            return True
        if remote_port and remote_port in self._suspicious_ports:
            return True
        return False

    # --- Public API methods ---

    def get_live_connections(self) -> list[dict]:
        """Return all cached live connections."""
        return self._connections

    def get_stats(self) -> dict:
        """Return connection statistics."""
        return {
            **self._stats,
            "last_scan": self._last_scan.isoformat() if self._last_scan else None,
        }

    def get_flagged_connections(self) -> list[dict]:
        """Return only flagged (suspicious) connections."""
        return self._flagged
