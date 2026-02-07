"""Process Analyzer Module — monitors running processes for suspicious behavior.

Polls psutil.process_iter() to track processes, detect suspicious executables,
monitor resource hogs, and build parent-child process trees.
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import Optional

import psutil

from .base_module import BaseModule

# Directories where legitimate executables typically reside
TRUSTED_DIRS = {
    os.environ.get("PROGRAMFILES", r"C:\Program Files"),
    os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
    os.environ.get("SYSTEMROOT", r"C:\Windows"),
}


class ProcessAnalyzer(BaseModule):
    """Monitors running processes for suspicious behavior and malware indicators."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="process_analyzer", config=config)

        cfg = config or {}
        self._poll_interval: int = cfg.get("poll_interval", 10)
        self._suspicious_names: list[str] = [
            n.lower() for n in cfg.get("suspicious_names", [])
        ]

        self._processes: dict[int, dict] = {}
        self._suspicious: list[dict] = []
        self._new_processes: list[dict] = []
        self._terminated_processes: list[dict] = []
        self._scan_task: Optional[asyncio.Task] = None
        self._last_scan: Optional[datetime] = None
        self._previous_pids: set[int] = set()

    async def start(self) -> None:
        self.running = True
        self.health_status = "running"
        self.logger.info("process_analyzer_starting")

        await self._scan_processes()
        self._scan_task = asyncio.create_task(self._poll_loop())
        self.heartbeat()
        self.logger.info("process_analyzer_started")

    async def stop(self) -> None:
        self.running = False
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        self.health_status = "stopped"
        self.logger.info("process_analyzer_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "total_processes": len(self._processes),
                "suspicious_count": len(self._suspicious),
                "last_scan": self._last_scan.isoformat() if self._last_scan else None,
            },
        }

    async def _poll_loop(self) -> None:
        while self.running:
            try:
                await asyncio.sleep(self._poll_interval)
                if self.running:
                    await self._scan_processes()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("process_scan_error", error=str(e))
                await asyncio.sleep(self._poll_interval)

    async def _scan_processes(self) -> None:
        loop = asyncio.get_event_loop()
        procs = await loop.run_in_executor(None, self._collect_processes)

        current_pids = set(procs.keys())
        new_pids = current_pids - self._previous_pids
        terminated_pids = self._previous_pids - current_pids

        self._new_processes = [procs[pid] for pid in new_pids if pid in procs]
        self._terminated_processes = [
            self._processes[pid] for pid in terminated_pids if pid in self._processes
        ]

        self._processes = procs
        self._suspicious = [p for p in procs.values() if p.get("suspicious")]
        self._previous_pids = current_pids
        self._last_scan = datetime.now(timezone.utc)
        self.heartbeat()

    def _collect_processes(self) -> dict[int, dict]:
        procs = {}
        attrs = ["pid", "name", "exe", "username", "cpu_percent", "memory_percent",
                 "status", "create_time", "ppid"]

        for proc in psutil.process_iter(attrs=attrs):
            try:
                info = proc.info
                pid = info["pid"]
                name = (info.get("name") or "").lower()
                exe = info.get("exe") or ""
                cpu = info.get("cpu_percent") or 0.0
                mem = info.get("memory_percent") or 0.0

                suspicious = False
                suspicious_reasons = []

                # Check against known suspicious names
                for sname in self._suspicious_names:
                    if sname in name:
                        suspicious = True
                        suspicious_reasons.append(f"known_malware_name:{sname}")

                # Check if running from untrusted location
                if exe and not any(exe.lower().startswith(d.lower()) for d in TRUSTED_DIRS if d):
                    if exe and os.path.isabs(exe):
                        suspicious_reasons.append("untrusted_location")
                        # Only flag as suspicious if also matching other criteria
                        # to reduce false positives for user apps

                # Check for high resource usage
                if cpu > 80:
                    suspicious_reasons.append(f"high_cpu:{cpu:.1f}%")
                    suspicious = True
                if mem > 50:
                    suspicious_reasons.append(f"high_memory:{mem:.1f}%")
                    suspicious = True

                create_time = None
                if info.get("create_time"):
                    try:
                        create_time = datetime.fromtimestamp(
                            info["create_time"], tz=timezone.utc
                        ).isoformat()
                    except (OSError, ValueError):
                        pass

                procs[pid] = {
                    "pid": pid,
                    "name": info.get("name") or "",
                    "exe": exe,
                    "username": info.get("username") or "",
                    "cpu_percent": cpu,
                    "memory_percent": mem,
                    "status": info.get("status") or "",
                    "create_time": create_time,
                    "ppid": info.get("ppid"),
                    "suspicious": suspicious,
                    "suspicious_reasons": suspicious_reasons,
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return procs

    # --- Public API ---

    def get_processes(self) -> list[dict]:
        return list(self._processes.values())

    def get_suspicious(self) -> list[dict]:
        return self._suspicious

    def get_new_processes(self) -> list[dict]:
        return self._new_processes

    def get_terminated_processes(self) -> list[dict]:
        return self._terminated_processes

    def get_process_tree(self, pid: int) -> dict | None:
        """Build parent-child tree for a given PID."""
        if pid not in self._processes:
            return None

        proc = self._processes[pid]
        children = [
            p for p in self._processes.values() if p.get("ppid") == pid
        ]

        return {
            **proc,
            "children": [
                self.get_process_tree(c["pid"]) or c for c in children
            ],
        }
