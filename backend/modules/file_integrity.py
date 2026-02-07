"""File Integrity Module — monitors files for unauthorized modifications.

Walks configured directories, computes SHA-256 hashes, and compares against
a baseline to detect added, modified, or deleted files.
"""

import asyncio
import fnmatch
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .base_module import BaseModule


class FileIntegrity(BaseModule):
    """Monitors critical files for unauthorized modifications."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="file_integrity", config=config)

        cfg = config or {}
        self._scan_interval: int = cfg.get("scan_interval", 300)
        self._watched_paths: list[str] = cfg.get("watched_paths", [])
        self._exclusion_patterns: list[str] = cfg.get("exclusion_patterns", [
            "*.tmp", "*.log", "*.pyc", "__pycache__", "*.pyo",
            ".git", "*.swp", "*.swo", "node_modules",
        ])
        self._max_file_size: int = cfg.get("max_file_size", 50_000_000)

        # State
        self._baselines: dict[str, str] = {}  # path -> sha256 hash
        self._last_scan: Optional[dict] = None
        self._scan_task: Optional[asyncio.Task] = None
        self._baseline_established: bool = False

    async def start(self) -> None:
        """Start the file integrity monitoring loop."""
        self.running = True
        self.health_status = "running"
        self.logger.info("file_integrity_starting")

        # Run initial baseline scan
        if self._watched_paths:
            await self.run_scan()

        # Start periodic scanning
        self._scan_task = asyncio.create_task(self._poll_loop())
        self.heartbeat()
        self.logger.info("file_integrity_started", watched_paths=len(self._watched_paths))

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
        self.logger.info("file_integrity_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "baseline_files": len(self._baselines),
                "baseline_established": self._baseline_established,
                "watched_paths": len(self._watched_paths),
                "last_scan": (
                    self._last_scan.get("timestamp") if self._last_scan else None
                ),
            },
        }

    async def _poll_loop(self) -> None:
        """Periodically run integrity scans."""
        while self.running:
            try:
                await asyncio.sleep(self._scan_interval)
                if self.running and self._watched_paths:
                    await self.run_scan()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("file_integrity_scan_error", error=str(e))
                await asyncio.sleep(self._scan_interval)

    async def run_scan(self) -> dict:
        """Run a file integrity scan. First scan establishes baseline."""
        loop = asyncio.get_event_loop()
        current_hashes = await loop.run_in_executor(None, self._compute_all_hashes)

        if not self._baseline_established:
            # First scan — establish baseline
            self._baselines = current_hashes
            self._baseline_established = True
            result = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "baseline",
                "files_scanned": len(current_hashes),
                "changes": {"modified": [], "added": [], "deleted": []},
            }
            self.logger.info(
                "file_integrity_baseline_established",
                files=len(current_hashes),
            )
        else:
            # Compare against baseline
            changes = self._compare_hashes(self._baselines, current_hashes)
            result = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "scan",
                "files_scanned": len(current_hashes),
                "changes": changes,
            }

            total_changes = (
                len(changes["modified"])
                + len(changes["added"])
                + len(changes["deleted"])
            )
            if total_changes > 0:
                self.logger.warning(
                    "file_integrity_changes_detected",
                    modified=len(changes["modified"]),
                    added=len(changes["added"]),
                    deleted=len(changes["deleted"]),
                )

            # Update baseline to current state
            self._baselines = current_hashes

        self._last_scan = result
        self.heartbeat()
        return result

    def _compute_all_hashes(self) -> dict[str, str]:
        """Walk watched directories and compute SHA-256 hashes."""
        hashes: dict[str, str] = {}
        for watched_path in self._watched_paths:
            path = Path(watched_path)
            if path.is_file():
                h = self._hash_file(path)
                if h is not None:
                    hashes[str(path)] = h
            elif path.is_dir():
                for root, dirs, files in os.walk(path):
                    # Filter excluded directories in-place
                    dirs[:] = [
                        d for d in dirs
                        if not self._is_excluded(d)
                    ]
                    for fname in files:
                        if self._is_excluded(fname):
                            continue
                        fpath = Path(root) / fname
                        h = self._hash_file(fpath)
                        if h is not None:
                            hashes[str(fpath)] = h
        return hashes

    def _hash_file(self, path: Path) -> Optional[str]:
        """Compute SHA-256 hash for a single file. Returns None if skipped."""
        try:
            if path.stat().st_size > self._max_file_size:
                return None
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha.update(chunk)
            return sha.hexdigest()
        except (OSError, PermissionError):
            return None

    def _is_excluded(self, name: str) -> bool:
        """Check if a file/dir name matches any exclusion pattern."""
        return any(fnmatch.fnmatch(name, pat) for pat in self._exclusion_patterns)

    @staticmethod
    def _compare_hashes(
        baseline: dict[str, str], current: dict[str, str]
    ) -> dict[str, list[str]]:
        """Compare baseline and current hashes to find changes."""
        baseline_keys = set(baseline.keys())
        current_keys = set(current.keys())

        added = sorted(current_keys - baseline_keys)
        deleted = sorted(baseline_keys - current_keys)
        modified = sorted(
            p for p in baseline_keys & current_keys
            if baseline[p] != current[p]
        )
        return {"modified": modified, "added": added, "deleted": deleted}

    # --- Public API methods ---

    def get_baselines(self) -> dict:
        """Return the current baseline data."""
        return {
            "established": self._baseline_established,
            "file_count": len(self._baselines),
            "files": {p: h for p, h in sorted(self._baselines.items())},
        }

    def get_last_scan(self) -> Optional[dict]:
        """Return the result of the last scan."""
        return self._last_scan

    def get_changes(self) -> list[dict]:
        """Return detected file changes from the last scan."""
        if not self._last_scan or self._last_scan.get("type") == "baseline":
            return []
        changes = self._last_scan.get("changes", {})
        result = []
        for path in changes.get("modified", []):
            result.append({"path": path, "status": "modified"})
        for path in changes.get("added", []):
            result.append({"path": path, "status": "added"})
        for path in changes.get("deleted", []):
            result.append({"path": path, "status": "deleted"})
        return result
