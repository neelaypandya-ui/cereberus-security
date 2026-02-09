"""Memory Scanner Module — Bond's reconnaissance for fileless threats.

Inspects process memory for injected code, shellcode, RWX regions,
unbacked executable memory, and YARA rule matches.
"""

import asyncio
import json
import os
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from .base_module import BaseModule
from ..utils.logging import get_logger

logger = get_logger("module.memory_scanner")


class MemoryScanner(BaseModule):
    """Periodic and on-demand process memory forensics."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="memory_scanner", config=config)

        cfg = config or {}
        self._scan_interval: int = cfg.get("scan_interval", 300)
        self._max_processes: int = cfg.get("max_processes", 200)
        self._rwx_alert_threshold: int = cfg.get("rwx_alert_threshold", 3)

        self._scan_task: Optional[asyncio.Task] = None
        self._last_scan: Optional[str] = None
        self._findings: deque[dict] = deque(maxlen=500)
        self._alert_manager = None
        self._yara_scanner = None
        self._db_session_factory = None
        self._event_bus = None

        # Stats
        self._total_scans: int = 0
        self._total_findings: int = 0
        self._processes_scanned: int = 0

        # Shellcode signatures
        self._shellcode_patterns = [
            (b"\x90" * 20, "NOP sled"),
            (b"\xfc\xe8", "Shellcode prolog (CLD+CALL)"),
            (b"\x60\x89\xe5\x31", "PUSHAD+MOV EBP,ESP+XOR"),
            (b"MZ", "PE header in memory"),
        ]

    def set_alert_manager(self, manager) -> None:
        self._alert_manager = manager

    def set_yara_scanner(self, scanner) -> None:
        self._yara_scanner = scanner

    def set_db_session_factory(self, factory) -> None:
        self._db_session_factory = factory

    def set_event_bus(self, bus) -> None:
        """Attach EventBus for publishing memory anomaly events."""
        self._event_bus = bus

    async def start(self) -> None:
        self.running = True
        self.health_status = "running"
        self.logger.info("memory_scanner_starting")

        # Run initial scan
        await self._run_scan()

        self._scan_task = asyncio.create_task(self._scan_loop())
        self.heartbeat()
        self.logger.info("memory_scanner_started")

    async def stop(self) -> None:
        self.running = False
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        self.health_status = "stopped"
        self.logger.info("memory_scanner_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "total_scans": self._total_scans,
                "total_findings": self._total_findings,
                "processes_scanned": self._processes_scanned,
                "last_scan": self._last_scan,
                "findings_buffered": len(self._findings),
            },
        }

    async def _scan_loop(self) -> None:
        while self.running:
            try:
                await asyncio.sleep(self._scan_interval)
                if self.running:
                    await self._run_scan()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("memory_scan_loop_error", error=str(e))
                await asyncio.sleep(self._scan_interval)

    async def _run_scan(self) -> list[dict]:
        """Scan all accessible processes for memory anomalies."""
        from ..utils import win32_memory as mem

        if not mem.is_available():
            self.logger.info("memory_scanner_skipped_not_windows")
            return []

        loop = asyncio.get_event_loop()
        findings = []

        try:
            pids = await loop.run_in_executor(None, self._enumerate_pids)
            scan_count = 0

            for pid, name in pids[:self._max_processes]:
                if not self.running:
                    break
                try:
                    process_findings = await loop.run_in_executor(
                        None, self._scan_process_sync, pid, name
                    )
                    findings.extend(process_findings)
                    scan_count += 1
                except Exception:
                    pass

            self._processes_scanned = scan_count
            self._total_scans += 1
            self._total_findings += len(findings)
            self._last_scan = datetime.now(timezone.utc).isoformat()

            for f in findings:
                self._findings.append(f)

            # Persist to DB
            if findings:
                await self._persist_findings(findings)

            # Create alerts and publish to EventBus for critical findings
            for f in findings:
                # Publish to EventBus
                if self._event_bus:
                    self._event_bus.publish("memory_anomaly", {
                        "event_type": "memory_anomaly",
                        "module_source": "memory_scanner",
                        "finding_type": f["finding_type"],
                        "severity": f["severity"],
                        "pid": f["pid"],
                        "process_name": f["process_name"],
                        "details": f.get("details", {}),
                    })

                if self._alert_manager and f["severity"] in ("critical", "high"):
                    try:
                        await self._alert_manager.create_alert(
                            severity=f["severity"],
                            module_source="memory_scanner",
                            title=f"Memory anomaly: {f['finding_type']} in {f['process_name']} (PID {f['pid']})",
                            description=json.dumps(f.get("details", {})),
                            details=f,
                        )
                    except Exception as e:
                        self.logger.error("memory_alert_failed", error=str(e))

            self.heartbeat()
            self.logger.info("memory_scan_complete", findings=len(findings), processes=scan_count)

        except Exception as e:
            self.logger.error("memory_scan_error", error=str(e))

        return findings

    def _enumerate_pids(self) -> list[tuple[int, str]]:
        """Enumerate running processes. Returns list of (pid, name)."""
        import ctypes
        import ctypes.wintypes

        pids = []
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    info = proc.info
                    if info["pid"] and info["pid"] > 4:  # Skip System/Idle
                        pids.append((info["pid"], info["name"] or "unknown"))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except ImportError:
            # Fallback: use os
            self.logger.warning("psutil_not_available_for_memory_scan")
        return pids

    def _scan_process_sync(self, pid: int, name: str) -> list[dict]:
        """Scan a single process for memory anomalies (synchronous)."""
        from ..utils import win32_memory as mem

        findings = []
        handle = mem.open_process(pid)
        if not handle:
            return findings

        try:
            regions = mem.virtual_query_ex(handle)
            rwx_count = 0
            unbacked_exec_count = 0

            for region in regions:
                if not region["is_committed"]:
                    continue

                # Detection 1: RWX regions (PAGE_EXECUTE_READWRITE)
                if region["is_rwx"]:
                    rwx_count += 1

                # Detection 2: Unbacked executable memory (executable + private, not image)
                if region["is_executable"] and region["is_private"] and not region["is_image"]:
                    unbacked_exec_count += 1

                    # Try to read and check for shellcode patterns
                    data = mem.read_process_memory(
                        handle, region["base_address"],
                        min(region["region_size"], 4096)
                    )
                    if data:
                        for pattern, pattern_name in self._shellcode_patterns:
                            if pattern in data:
                                findings.append(self._make_finding(
                                    pid, name, "shellcode",
                                    "critical",
                                    {
                                        "pattern": pattern_name,
                                        "address": hex(region["base_address"]),
                                        "region_size": region["region_size"],
                                        "protection": mem.get_protection_string(region["protect"]),
                                    },
                                ))
                                break  # One finding per region

            # Report RWX regions if above threshold
            if rwx_count >= self._rwx_alert_threshold:
                findings.append(self._make_finding(
                    pid, name, "rwx_region",
                    "high",
                    {"rwx_region_count": rwx_count},
                ))

            # Report unbacked executable regions
            if unbacked_exec_count > 0:
                findings.append(self._make_finding(
                    pid, name, "unbacked_exec",
                    "high",
                    {"unbacked_exec_count": unbacked_exec_count},
                ))

            # Detection 3: Injected DLLs (modules not on disk)
            modules = mem.enum_process_modules(handle)
            for mod in modules:
                mod_path = mod.get("path", "")
                if mod_path and not os.path.exists(mod_path):
                    findings.append(self._make_finding(
                        pid, name, "injected_dll",
                        "critical",
                        {"module_path": mod_path, "module_name": mod.get("name", "")},
                    ))

        finally:
            mem.close_handle(handle)

        return findings

    @staticmethod
    def _make_finding(pid: int, name: str, finding_type: str, severity: str, details: dict) -> dict:
        return {
            "pid": pid,
            "process_name": name,
            "finding_type": finding_type,
            "severity": severity,
            "details": details,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    async def scan_process(self, pid: int) -> list[dict]:
        """On-demand scan of a specific process."""
        from ..utils import win32_memory as mem

        if not mem.is_available():
            return []

        loop = asyncio.get_event_loop()
        # Get process name
        name = "unknown"
        try:
            import psutil
            proc = psutil.Process(pid)
            name = proc.name()
        except Exception:
            pass

        findings = await loop.run_in_executor(None, self._scan_process_sync, pid, name)

        # Also run YARA scan if available
        if self._yara_scanner:
            try:
                yara_matches = await self._yara_scanner.scan_process_memory(pid, triggered_by="memory_scanner")
                for match in yara_matches:
                    findings.append(self._make_finding(
                        pid, name, "yara_match",
                        match.get("severity", "high"),
                        {"rule_name": match.get("rule_name", ""), "meta": match.get("meta_json", "")},
                    ))
            except Exception as e:
                self.logger.error("memory_yara_scan_error", pid=pid, error=str(e))

        for f in findings:
            self._findings.append(f)

        if findings:
            await self._persist_findings(findings)

        return findings

    async def get_process_regions(self, pid: int) -> list[dict]:
        """Get memory regions for a specific process."""
        from ..utils import win32_memory as mem

        if not mem.is_available():
            return []

        loop = asyncio.get_event_loop()

        def _query():
            handle = mem.open_process(pid)
            if not handle:
                return []
            try:
                regions = mem.virtual_query_ex(handle)
                return [
                    {
                        "base_address": hex(r["base_address"]) if r["base_address"] else "0x0",
                        "region_size": r["region_size"],
                        "protection": mem.get_protection_string(r["protect"]),
                        "state": "committed" if r["is_committed"] else "reserved" if r["state"] == 0x2000 else "free",
                        "type": "image" if r["is_image"] else "private" if r["is_private"] else "mapped",
                        "is_rwx": r["is_rwx"],
                        "is_executable": r["is_executable"],
                    }
                    for r in regions if r["is_committed"]
                ]
            finally:
                mem.close_handle(handle)

        return await loop.run_in_executor(None, _query)

    async def _persist_findings(self, findings: list[dict]) -> None:
        if not self._db_session_factory:
            return
        try:
            from ..models.memory_scan_result import MemoryScanResult
            async with self._db_session_factory() as session:
                for f in findings:
                    session.add(MemoryScanResult(
                        pid=f["pid"],
                        process_name=f["process_name"],
                        finding_type=f["finding_type"],
                        severity=f["severity"],
                        details_json=json.dumps(f.get("details", {})),
                    ))
                await session.commit()
        except Exception as e:
            self.logger.error("memory_persist_error", error=str(e))

    def get_findings(self, limit: int = 100) -> list[dict]:
        findings = list(self._findings)
        findings.reverse()
        return findings[:limit]

    def get_status(self) -> dict:
        return {
            "running": self.running,
            "total_scans": self._total_scans,
            "total_findings": self._total_findings,
            "processes_scanned": self._processes_scanned,
            "last_scan": self._last_scan,
            "findings_buffered": len(self._findings),
        }
