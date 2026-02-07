"""Persistence Scanner Module — detects autorun persistence mechanisms.

Scans Windows autorun locations (registry Run keys, startup folders, scheduled
tasks) and detects changes from a baseline to identify newly added persistence.
"""

import asyncio
import csv
import io
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .base_module import BaseModule

# Registry paths to scan for persistence
REGISTRY_PATHS = [
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
    (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
    (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
]


class PersistenceScanner(BaseModule):
    """Scans Windows autorun locations for persistence mechanisms."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="persistence_scanner", config=config)

        cfg = config or {}
        self._scan_interval: int = cfg.get("scan_interval", 600)

        self._entries: list[dict] = []
        self._baseline: list[dict] = []
        self._changes: list[dict] = []
        self._baseline_established: bool = False
        self._last_scan: Optional[datetime] = None
        self._scan_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self.running = True
        self.health_status = "running"
        self.logger.info("persistence_scanner_starting")

        await self.run_scan()

        self._scan_task = asyncio.create_task(self._poll_loop())
        self.heartbeat()
        self.logger.info("persistence_scanner_started")

    async def stop(self) -> None:
        self.running = False
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        self.health_status = "stopped"
        self.logger.info("persistence_scanner_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "entry_count": len(self._entries),
                "change_count": len(self._changes),
                "baseline_established": self._baseline_established,
                "last_scan": self._last_scan.isoformat() if self._last_scan else None,
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
                self.logger.error("persistence_scan_error", error=str(e))
                await asyncio.sleep(self._scan_interval)

    async def run_scan(self) -> dict:
        """Run a persistence scan. First scan establishes baseline."""
        loop = asyncio.get_event_loop()
        entries = await loop.run_in_executor(None, self._collect_all_entries)

        if not self._baseline_established:
            self._baseline = entries
            self._baseline_established = True
            self._changes = []
            self.logger.info("persistence_baseline_established", entries=len(entries))
        else:
            self._changes = self._compute_changes(self._baseline, entries)
            if self._changes:
                self.logger.warning(
                    "persistence_changes_detected",
                    added=sum(1 for c in self._changes if c["status"] == "added"),
                    removed=sum(1 for c in self._changes if c["status"] == "removed"),
                    changed=sum(1 for c in self._changes if c["status"] == "changed"),
                )
            self._baseline = entries

        self._entries = entries
        self._last_scan = datetime.now(timezone.utc)
        self.heartbeat()

        return {
            "entries": len(entries),
            "changes": len(self._changes),
            "timestamp": self._last_scan.isoformat(),
        }

    def _collect_all_entries(self) -> list[dict]:
        """Collect all autorun entries from registry, startup folders, and scheduled tasks."""
        entries = []
        entries.extend(self._scan_registry())
        entries.extend(self._scan_startup_folders())
        entries.extend(self._scan_scheduled_tasks())
        return entries

    def _scan_registry(self) -> list[dict]:
        """Scan Windows registry Run/RunOnce keys."""
        entries = []
        try:
            import winreg
        except ImportError:
            return entries

        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }

        for reg_path, source_label in REGISTRY_PATHS:
            hive_prefix = reg_path.split("\\")[0]
            subkey = "\\".join(reg_path.split("\\")[1:])
            hive = hive_map.get(hive_prefix)
            if hive is None:
                continue

            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                try:
                    i = 0
                    while True:
                        name, value, _ = winreg.EnumValue(key, i)
                        entries.append({
                            "source": "registry",
                            "source_label": source_label,
                            "path": reg_path,
                            "name": name,
                            "value": str(value),
                        })
                        i += 1
                except OSError:
                    pass
                finally:
                    winreg.CloseKey(key)
            except OSError:
                continue

        return entries

    def _scan_startup_folders(self) -> list[dict]:
        """Scan user and all-users startup folders."""
        entries = []
        folders = []

        # Current user startup
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            folders.append(
                Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            )

        # All users startup
        programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        folders.append(
            Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        )

        for folder in folders:
            if not folder.exists():
                continue
            try:
                for item in folder.iterdir():
                    entries.append({
                        "source": "startup_folder",
                        "source_label": str(folder),
                        "path": str(item),
                        "name": item.name,
                        "value": str(item),
                    })
            except (PermissionError, OSError):
                continue

        return entries

    def _scan_scheduled_tasks(self) -> list[dict]:
        """Parse scheduled tasks via schtasks command."""
        entries = []
        try:
            import subprocess
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/nh"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                reader = csv.reader(io.StringIO(result.stdout.strip()))
                for row in reader:
                    if len(row) >= 2 and row[0].strip():
                        task_name = row[0].strip().strip('"')
                        # Skip Microsoft system tasks
                        if task_name.startswith("\\Microsoft\\"):
                            continue
                        entries.append({
                            "source": "scheduled_task",
                            "source_label": "Task Scheduler",
                            "path": task_name,
                            "name": task_name.split("\\")[-1],
                            "value": row[1].strip().strip('"') if len(row) > 1 else "",
                        })
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return entries

    @staticmethod
    def _compute_changes(baseline: list[dict], current: list[dict]) -> list[dict]:
        """Compare baseline and current entries to find changes."""
        def entry_key(e: dict) -> str:
            return f"{e['source']}::{e['path']}::{e['name']}"

        baseline_map = {entry_key(e): e for e in baseline}
        current_map = {entry_key(e): e for e in current}

        changes = []
        # Added entries
        for key, entry in current_map.items():
            if key not in baseline_map:
                changes.append({**entry, "status": "added"})
            elif entry.get("value") != baseline_map[key].get("value"):
                changes.append({**entry, "status": "changed", "old_value": baseline_map[key].get("value")})

        # Removed entries
        for key, entry in baseline_map.items():
            if key not in current_map:
                changes.append({**entry, "status": "removed"})

        return changes

    # --- Public API ---

    def get_entries(self) -> list[dict]:
        return self._entries

    def get_changes(self) -> list[dict]:
        return self._changes

    def get_last_scan(self) -> Optional[dict]:
        if not self._last_scan:
            return None
        return {
            "timestamp": self._last_scan.isoformat(),
            "entry_count": len(self._entries),
            "change_count": len(self._changes),
            "baseline_established": self._baseline_established,
        }
