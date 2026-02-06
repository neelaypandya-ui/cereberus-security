"""Brute Force Shield Module — detects and blocks brute-force login attacks.

Reads Windows Security Event Log (Event ID 4625 = failed logon) via PowerShell,
tracks failed attempts per IP in a sliding time window, and auto-blocks IPs
exceeding the threshold using Windows Firewall rules.
"""

import asyncio
import json
import subprocess
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

from .base_module import BaseModule

CEREBERUS_RULE_PREFIX = "CEREBERUS_BLOCK_"


class BruteForceShield(BaseModule):
    """Detects brute-force attacks and auto-blocks offending IPs."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="brute_force_shield", config=config)

        cfg = config or {}
        self._poll_interval: int = cfg.get("poll_interval", 10)
        self._threshold: int = cfg.get("threshold", 5)
        self._window_seconds: int = cfg.get("window_seconds", 300)
        self._block_duration: int = cfg.get("block_duration", 3600)
        self._whitelist_ips: set[str] = set(cfg.get("whitelist_ips", ["127.0.0.1", "::1"]))

        # State
        self._failed_attempts: dict[str, list[datetime]] = defaultdict(list)
        self._blocked_ips: dict[str, datetime] = {}  # ip -> blocked_at
        self._recent_events: list[dict] = []
        self._last_record_id: int = 0
        self._poll_task: Optional[asyncio.Task] = None
        self._unblock_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start monitoring the Windows Security Event Log."""
        self.running = True
        self.health_status = "running"
        self.logger.info("brute_force_shield_starting")

        # Initial poll
        await self._poll_events()

        # Start polling and unblock loops
        self._poll_task = asyncio.create_task(self._poll_loop())
        self._unblock_task = asyncio.create_task(self._unblock_loop())

        self.heartbeat()
        self.logger.info("brute_force_shield_started")

    async def stop(self) -> None:
        """Stop monitoring and clean up firewall rules."""
        self.running = False

        for task in [self._poll_task, self._unblock_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Clean up all Cereberus firewall rules
        await self._cleanup_firewall_rules()

        self.health_status = "stopped"
        self.logger.info("brute_force_shield_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "blocked_ips": len(self._blocked_ips),
                "tracked_ips": len(self._failed_attempts),
                "recent_events": len(self._recent_events),
                "threshold": self._threshold,
                "window_seconds": self._window_seconds,
            },
        }

    async def _poll_loop(self) -> None:
        """Periodically poll Windows Event Log."""
        while self.running:
            try:
                await asyncio.sleep(self._poll_interval)
                if self.running:
                    await self._poll_events()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("brute_force_poll_error", error=str(e))
                await asyncio.sleep(self._poll_interval)

    async def _unblock_loop(self) -> None:
        """Periodically check for IPs that should be unblocked."""
        while self.running:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                if not self.running:
                    break
                now = datetime.now(timezone.utc)
                expired = [
                    ip for ip, blocked_at in self._blocked_ips.items()
                    if (now - blocked_at).total_seconds() >= self._block_duration
                ]
                for ip in expired:
                    await self._unblock_ip(ip)
                    self.logger.info("brute_force_auto_unblock", ip=ip)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("brute_force_unblock_error", error=str(e))

    async def _poll_events(self) -> None:
        """Read failed logon events (4625) from Windows Security Event Log."""
        loop = asyncio.get_event_loop()
        try:
            events = await loop.run_in_executor(None, self._read_event_log)
        except Exception as e:
            self.logger.error("event_log_read_failed", error=str(e))
            return

        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self._window_seconds)

        for event in events:
            source_ip = event.get("source_ip", "")
            if not source_ip or source_ip in self._whitelist_ips or source_ip == "-":
                continue

            # Track the attempt
            self._failed_attempts[source_ip].append(now)
            self._recent_events.append(event)

            # Prune old attempts outside the window
            self._failed_attempts[source_ip] = [
                t for t in self._failed_attempts[source_ip]
                if t >= window_start
            ]

            # Check threshold
            if (
                len(self._failed_attempts[source_ip]) >= self._threshold
                and source_ip not in self._blocked_ips
            ):
                await self._block_ip(source_ip)
                event["blocked"] = True

        # Keep recent events list manageable
        if len(self._recent_events) > 500:
            self._recent_events = self._recent_events[-500:]

        self.heartbeat()

    def _read_event_log(self) -> list[dict]:
        """Read Event ID 4625 from Windows Security log via PowerShell."""
        ps_script = (
            "try { "
            "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} "
            "-MaxEvents 50 -ErrorAction Stop | "
            "ForEach-Object { "
            "$xml = [xml]$_.ToXml(); "
            "$ns = @{e='http://schemas.microsoft.com/win/2004/08/events/event'}; "
            "$ip = $xml.SelectSingleNode('//e:Data[@Name=\"IpAddress\"]', "
            "(New-Object System.Xml.XmlNamespaceManager($xml.NameTable)).tap{"
            '$_.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event")}'
            ").'#text'; "
            "$user = $xml.SelectSingleNode('//e:Data[@Name=\"TargetUserName\"]', "
            "(New-Object System.Xml.XmlNamespaceManager($xml.NameTable)).tap{"
            '$_.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event")}'
            ").'#text'; "
            "$svc = $xml.SelectSingleNode('//e:Data[@Name=\"LogonType\"]', "
            "(New-Object System.Xml.XmlNamespaceManager($xml.NameTable)).tap{"
            '$_.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event")}'
            ").'#text'; "
            "@{RecordId=$_.RecordId;TimeCreated=$_.TimeCreated.ToString('o');"
            "SourceIP=$ip;Username=$user;LogonType=$svc} } | "
            "ConvertTo-Json -Compress "
            "} catch { '[]' }"
        )

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout.strip()
            if not output or output == "[]":
                return []

            data = json.loads(output)
            if isinstance(data, dict):
                data = [data]

            events = []
            for entry in data:
                record_id = entry.get("RecordId", 0)
                if record_id <= self._last_record_id:
                    continue
                self._last_record_id = max(self._last_record_id, record_id)

                events.append({
                    "timestamp": entry.get("TimeCreated", ""),
                    "source_ip": entry.get("SourceIP", ""),
                    "username": entry.get("Username", ""),
                    "target_service": self._logon_type_name(entry.get("LogonType", "")),
                    "event_id": 4625,
                    "event_record_id": record_id,
                    "success": False,
                    "blocked": False,
                })
            return events
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return []

    @staticmethod
    def _logon_type_name(logon_type: str) -> str:
        """Map Windows logon type number to a human-readable service name."""
        mapping = {
            "2": "Interactive (Console)",
            "3": "Network (SMB/RDP-NLA)",
            "4": "Batch",
            "5": "Service",
            "7": "Unlock",
            "8": "NetworkCleartext",
            "9": "NewCredentials",
            "10": "RemoteInteractive (RDP)",
            "11": "CachedInteractive",
        }
        return mapping.get(str(logon_type), f"Type {logon_type}")

    async def _block_ip(self, ip: str) -> None:
        """Block an IP via Windows Firewall."""
        rule_name = f"{CEREBERUS_RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=block",
            f"remoteip={ip}",
            "enable=yes",
        ]
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: subprocess.run(cmd, capture_output=True, timeout=10),
            )
            self._blocked_ips[ip] = datetime.now(timezone.utc)
            self.logger.warning("brute_force_ip_blocked", ip=ip)
        except Exception as e:
            self.logger.error("brute_force_block_failed", ip=ip, error=str(e))

    async def _unblock_ip(self, ip: str) -> None:
        """Remove firewall block rule for an IP."""
        rule_name = f"{CEREBERUS_RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ]
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: subprocess.run(cmd, capture_output=True, timeout=10),
            )
            self._blocked_ips.pop(ip, None)
            self.logger.info("brute_force_ip_unblocked", ip=ip)
        except Exception as e:
            self.logger.error("brute_force_unblock_failed", ip=ip, error=str(e))

    async def _cleanup_firewall_rules(self) -> None:
        """Remove all Cereberus firewall rules on shutdown."""
        for ip in list(self._blocked_ips.keys()):
            await self._unblock_ip(ip)

    # --- Public API methods ---

    def get_recent_events(self, limit: int = 50) -> list[dict]:
        """Return recent brute-force events."""
        return list(reversed(self._recent_events[-limit:]))

    def get_blocked_ips(self) -> list[dict]:
        """Return currently blocked IPs."""
        now = datetime.now(timezone.utc)
        return [
            {
                "ip": ip,
                "blocked_at": blocked_at.isoformat(),
                "remaining_seconds": max(
                    0,
                    self._block_duration - int((now - blocked_at).total_seconds()),
                ),
            }
            for ip, blocked_at in self._blocked_ips.items()
        ]

    async def unblock_ip(self, ip: str) -> dict:
        """Manually unblock an IP address."""
        if ip in self._blocked_ips:
            await self._unblock_ip(ip)
            return {"ip": ip, "status": "unblocked"}
        return {"ip": ip, "status": "not_found"}
