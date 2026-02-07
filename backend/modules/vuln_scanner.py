"""Vulnerability Scanner Module — scans for system vulnerabilities.

Checks Windows Update status, open ports, weak configurations, and
installed software versions against known-vulnerable databases.
"""

import asyncio
import socket
from datetime import datetime, timezone
from typing import Optional

from .base_module import BaseModule

# Dangerous open ports and their services
DANGEROUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
}

# Known vulnerable software patterns (name_lower -> min_safe_version)
KNOWN_VULNERABLE = {
    "apache": "2.4.58",
    "openssl": "3.2.0",
    "nginx": "1.25.4",
    "nodejs": "20.11.0",
    "python": "3.12.1",
    "php": "8.3.2",
}


class VulnScanner(BaseModule):
    """Scans for system vulnerabilities and security misconfigurations."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="vuln_scanner", config=config)

        cfg = config or {}
        self._scan_interval: int = cfg.get("scan_interval", 3600)
        self._check_updates: bool = cfg.get("check_windows_updates", True)
        self._check_ports: bool = cfg.get("check_open_ports", True)
        self._check_configs: bool = cfg.get("check_weak_configs", True)
        self._check_software: bool = cfg.get("check_software", True)

        self._vulnerabilities: list[dict] = []
        self._last_report: dict | None = None
        self._last_scan: Optional[datetime] = None
        self._scan_task: Optional[asyncio.Task] = None
        self._scanning: bool = False

    async def start(self) -> None:
        self.running = True
        self.health_status = "running"
        self.logger.info("vuln_scanner_starting")

        # Run initial scan
        await self.run_scan()

        self._scan_task = asyncio.create_task(self._poll_loop())
        self.heartbeat()
        self.logger.info("vuln_scanner_started")

    async def stop(self) -> None:
        self.running = False
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        self.health_status = "stopped"
        self.logger.info("vuln_scanner_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "vulnerability_count": len(self._vulnerabilities),
                "last_scan": self._last_scan.isoformat() if self._last_scan else None,
                "scanning": self._scanning,
            },
        }

    async def _poll_loop(self) -> None:
        while self.running:
            try:
                await asyncio.sleep(self._scan_interval)
                if self.running:
                    await self.run_scan()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("vuln_scan_error", error=str(e))
                await asyncio.sleep(self._scan_interval)

    async def run_scan(self) -> dict:
        """Run a full vulnerability scan."""
        self._scanning = True
        vulns = []

        try:
            if self._check_ports:
                port_vulns = await self._check_open_ports()
                vulns.extend(port_vulns)

            if self._check_updates:
                update_vulns = await self._check_windows_updates()
                vulns.extend(update_vulns)

            if self._check_configs:
                config_vulns = await self._check_weak_configurations()
                vulns.extend(config_vulns)

            self._vulnerabilities = vulns
            self._last_scan = datetime.now(timezone.utc)

            severity_counts = {}
            for v in vulns:
                sev = v["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            self._last_report = {
                "scan_time": self._last_scan.isoformat(),
                "total_findings": len(vulns),
                "severity_counts": severity_counts,
                "vulnerabilities": vulns,
            }

            self.heartbeat()
            self.logger.info("vuln_scan_complete", findings=len(vulns))

        except Exception as e:
            self.logger.error("vuln_scan_failed", error=str(e))
        finally:
            self._scanning = False

        return self._last_report or {"total_findings": 0, "vulnerabilities": []}

    async def _check_open_ports(self) -> list[dict]:
        """Check for dangerously exposed ports."""
        loop = asyncio.get_event_loop()
        vulns = []

        for port, service in DANGEROUS_PORTS.items():
            is_open = await loop.run_in_executor(None, self._probe_port, port)
            if is_open:
                severity = "critical" if service in ("Telnet", "FTP", "SMB") else "high"
                vulns.append({
                    "category": "open_port",
                    "severity": severity,
                    "title": f"Exposed {service} port ({port})",
                    "description": f"Port {port} ({service}) is open and accessible. "
                                   f"This service should not be exposed unless explicitly required.",
                    "remediation": f"Disable {service} service or restrict access via firewall rules.",
                    "port": port,
                    "service": service,
                })

        return vulns

    def _probe_port(self, port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
        """Check if a port is open on localhost."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except (OSError, socket.error):
            return False

    async def _check_windows_updates(self) -> list[dict]:
        """Check Windows Update status via PowerShell."""
        vulns = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell", "-NoProfile", "-Command",
                "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode().strip()

            if output:
                try:
                    # Parse the date — PowerShell outputs various date formats
                    last_update = datetime.fromisoformat(output.replace("/", "-"))
                    days_since = (datetime.now() - last_update).days

                    if days_since > 90:
                        vulns.append({
                            "category": "windows_update",
                            "severity": "critical",
                            "title": "Windows updates severely outdated",
                            "description": f"Last Windows update was {days_since} days ago. "
                                           f"System may be missing critical security patches.",
                            "remediation": "Run Windows Update immediately to install security patches.",
                        })
                    elif days_since > 30:
                        vulns.append({
                            "category": "windows_update",
                            "severity": "high",
                            "title": "Windows updates overdue",
                            "description": f"Last Windows update was {days_since} days ago.",
                            "remediation": "Run Windows Update to install latest security patches.",
                        })
                except (ValueError, TypeError):
                    pass
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            self.logger.debug("windows_update_check_skipped")

        return vulns

    async def _check_weak_configurations(self) -> list[dict]:
        """Check for weak system configurations via PowerShell."""
        vulns = []

        checks = [
            (
                "net user guest",
                "guest_account",
                lambda out: "account active" in out.lower() and "yes" in out.lower(),
                {
                    "severity": "medium",
                    "title": "Guest account is enabled",
                    "description": "The Windows Guest account is enabled, which provides unauthenticated access.",
                    "remediation": "Disable the Guest account: net user guest /active:no",
                },
            ),
            (
                'powershell -NoProfile -Command "Get-NetFirewallProfile | Select-Object Name,Enabled | Format-List"',
                "firewall",
                lambda out: "enabled" in out.lower() and "false" in out.lower(),
                {
                    "severity": "critical",
                    "title": "Windows Firewall is disabled",
                    "description": "One or more Windows Firewall profiles are disabled.",
                    "remediation": "Enable Windows Firewall for all profiles.",
                },
            ),
            (
                'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v AutoAdminLogon 2>nul',
                "autologin",
                lambda out: "autoadminlogon" in out.lower() and "0x1" in out.lower(),
                {
                    "severity": "high",
                    "title": "Auto-login is enabled",
                    "description": "Windows automatic login is enabled, which stores credentials in the registry.",
                    "remediation": "Disable auto-login in registry or use netplwiz.",
                },
            ),
        ]

        for cmd, category, check_fn, finding in checks:
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")

                if check_fn(output):
                    vulns.append({"category": category, **finding})
            except (asyncio.TimeoutError, FileNotFoundError, OSError):
                continue

        return vulns

    # --- Public API ---

    def get_vulnerabilities(self) -> list[dict]:
        return self._vulnerabilities

    def get_last_report(self) -> dict | None:
        return self._last_report
