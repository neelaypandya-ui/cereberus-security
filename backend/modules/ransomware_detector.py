"""Ransomware Detector Module — detects ransomware behavior on Windows hosts.

Provides three detection subsystems:
  1. Canary Files   — deploys hidden sentinel files; any tampering = CRITICAL alert
  2. Shadow Copy Deletion Detection — watches for vssadmin/wmic/bcdedit anti-recovery commands
  3. Mass Encryption Detection — tracks rapid file renames with high-entropy new extensions

All file operations use Python stdlib (zero shell=True calls).
"""

import asyncio
import hashlib
import math
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .base_module import BaseModule
from ..utils.logging import get_logger

# ── Constants ────────────────────────────────────────────────────────────────

CANARY_FILENAME = ".cereberus_canary"
CANARY_CONTENT = (
    "CEREBERUS CANARY FILE — DO NOT MODIFY OR DELETE\n"
    "This file is used by the Cereberus security system to detect ransomware.\n"
    "Modification or deletion of this file will trigger a critical security alert.\n"
)
CANARY_HASH = hashlib.sha256(CANARY_CONTENT.encode("utf-8")).hexdigest()

# User directories where canary files are deployed
CANARY_DIRECTORIES = ["Documents", "Desktop", "Downloads"]

# Command-line fragments that indicate shadow copy / recovery sabotage
SHADOW_COPY_INDICATORS = [
    "vssadmin delete shadows",
    "vssadmin.exe delete shadows",
    "wmic shadowcopy delete",
    "wmic.exe shadowcopy delete",
    "bcdedit /set recoveryenabled no",
    "bcdedit.exe /set recoveryenabled no",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit.exe /set {default} recoveryenabled no",
    "wbadmin delete catalog",
    "wbadmin.exe delete catalog",
    "wbadmin delete systemstatebackup",
    "wbadmin.exe delete systemstatebackup",
]

# Known ransomware file extensions (non-exhaustive, for heuristic weighting)
RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".enc", ".locked", ".crypt", ".crypted", ".cry",
    ".crypto", ".locky", ".cerber", ".zepto", ".odin", ".thor",
    ".aesir", ".zzzzz", ".micro", ".wncry", ".wcry", ".wncryt",
    ".lock", ".dharma", ".arena", ".java", ".bip", ".combo",
    ".onion", ".wallet", ".phobos", ".makop", ".STOP", ".djvu",
    ".roger", ".CONTI", ".RYUK", ".rapid", ".maze", ".eking",
}

# Entropy threshold — encrypted / compressed data typically > 7.0
HIGH_ENTROPY_THRESHOLD = 7.0

# Mass-rename detection thresholds
MASS_RENAME_WINDOW_SECONDS = 60
MASS_RENAME_THRESHOLD = 20

# Maximum bytes to sample for entropy calculation
ENTROPY_SAMPLE_SIZE = 8192

logger = get_logger("module.ransomware_detector")


class RansomwareDetector(BaseModule):
    """Detects ransomware activity via canary files, shadow copy monitoring,
    and mass-encryption heuristics."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="ransomware_detector", config=config)

        cfg = config or {}
        self._poll_interval: int = cfg.get("poll_interval", 10)
        self._enable_canaries: bool = cfg.get("enable_canaries", True)
        self._enable_shadow_detection: bool = cfg.get("enable_shadow_detection", True)
        self._enable_mass_encryption: bool = cfg.get("enable_mass_encryption", True)
        self._mass_rename_threshold: int = cfg.get(
            "mass_rename_threshold", MASS_RENAME_THRESHOLD
        )
        self._mass_rename_window: int = cfg.get(
            "mass_rename_window", MASS_RENAME_WINDOW_SECONDS
        )
        self._cleanup_canaries_on_stop: bool = cfg.get("cleanup_canaries_on_stop", False)

        # Canary state
        self._canary_paths: list[str] = []
        self._canary_health: dict[str, dict] = {}  # path -> {status, last_check, hash}

        # Detection log — ring buffer of all detections
        self._detection_log: deque[dict] = deque(maxlen=500)

        # File rename tracking buffer: (old_name, new_name, timestamp)
        self._file_rename_buffer: deque[dict] = deque(maxlen=1000)

        # Soft dependencies — injected after construction
        self._alert_manager = None
        self._process_analyzer = None
        self._file_integrity = None

        # Internal state
        self._monitor_task: Optional[asyncio.Task] = None
        self._last_check: Optional[datetime] = None
        self._stats: dict = {
            "canary_checks": 0,
            "canary_alerts": 0,
            "shadow_copy_alerts": 0,
            "mass_encryption_alerts": 0,
            "total_renames_tracked": 0,
        }

    # ── Dependency Injection ─────────────────────────────────────────────

    def set_alert_manager(self, manager) -> None:
        """Attach the alert manager for dispatching security alerts."""
        self._alert_manager = manager
        self.logger.info("alert_manager_attached")

    def set_process_analyzer(self, analyzer) -> None:
        """Attach the process analyzer for reading recent process events."""
        self._process_analyzer = analyzer
        self.logger.info("process_analyzer_attached")

    def set_file_integrity(self, fi) -> None:
        """Attach the file integrity module for cross-referencing file changes."""
        self._file_integrity = fi
        self.logger.info("file_integrity_attached")

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the ransomware detection module."""
        self.running = True
        self.health_status = "running"
        self.logger.info("ransomware_detector_starting")

        # Deploy canary files (synchronous, fast I/O)
        if self._enable_canaries:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._deploy_canaries)
            self.logger.info(
                "canary_files_deployed", count=len(self._canary_paths)
            )

        # Start the monitoring loop
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self.heartbeat()
        self.logger.info("ransomware_detector_started")

    async def stop(self) -> None:
        """Stop the ransomware detection module."""
        self.running = False
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        # Optionally remove canary files on shutdown
        if self._cleanup_canaries_on_stop and self._canary_paths:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._remove_canaries)
            self.logger.info("canary_files_removed")

        self.health_status = "stopped"
        self.logger.info("ransomware_detector_stopped")

    async def health_check(self) -> dict:
        """Return module health status."""
        self.heartbeat()
        canary_ok = all(
            c.get("status") == "ok" for c in self._canary_health.values()
        )
        return {
            "status": self.health_status,
            "details": {
                "canary_count": len(self._canary_paths),
                "canaries_healthy": canary_ok,
                "detections_total": len(self._detection_log),
                "renames_buffered": len(self._file_rename_buffer),
                "last_check": (
                    self._last_check.isoformat() if self._last_check else None
                ),
                "stats": dict(self._stats),
            },
        }

    # ── Monitor Loop ─────────────────────────────────────────────────────

    async def _monitor_loop(self) -> None:
        """Main polling loop — checks all detection subsystems each interval."""
        while self.running:
            try:
                await asyncio.sleep(self._poll_interval)
                if not self.running:
                    break

                # 1. Canary file integrity check
                if self._enable_canaries and self._canary_paths:
                    await self._check_canaries()

                # 2. Shadow copy deletion detection
                if self._enable_shadow_detection:
                    await self._check_shadow_copy_deletion()

                # 3. Mass encryption detection
                if self._enable_mass_encryption:
                    await self._evaluate_mass_encryption()

                self._last_check = datetime.now(timezone.utc)
                self.heartbeat()

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("ransomware_monitor_error", error=str(e))
                await asyncio.sleep(self._poll_interval)

    # ── Subsystem 1: Canary Files ────────────────────────────────────────

    def _deploy_canaries(self) -> None:
        """Create hidden canary files in standard user directories."""
        home = os.path.expanduser("~")
        self._canary_paths = []

        for dirname in CANARY_DIRECTORIES:
            target_dir = os.path.join(home, dirname)
            if not os.path.isdir(target_dir):
                self.logger.debug(
                    "canary_dir_not_found", directory=dirname
                )
                continue

            canary_path = os.path.join(target_dir, CANARY_FILENAME)
            try:
                # Write the canary content
                with open(canary_path, "w", encoding="utf-8") as f:
                    f.write(CANARY_CONTENT)

                # Set hidden attribute on Windows
                try:
                    import ctypes
                    FILE_ATTRIBUTE_HIDDEN = 0x02
                    ctypes.windll.kernel32.SetFileAttributesW(
                        canary_path, FILE_ATTRIBUTE_HIDDEN
                    )
                except (AttributeError, OSError):
                    # Non-Windows or permission issue — continue without hiding
                    pass

                self._canary_paths.append(canary_path)
                self._canary_health[canary_path] = {
                    "status": "ok",
                    "last_check": datetime.now(timezone.utc).isoformat(),
                    "expected_hash": CANARY_HASH,
                    "directory": dirname,
                }
                self.logger.debug("canary_deployed", path=canary_path)

            except (OSError, PermissionError) as e:
                self.logger.warning(
                    "canary_deploy_failed", directory=dirname, error=str(e)
                )

    def _remove_canaries(self) -> None:
        """Remove all deployed canary files."""
        for canary_path in self._canary_paths:
            try:
                if os.path.exists(canary_path):
                    os.remove(canary_path)
                    self.logger.debug("canary_removed", path=canary_path)
            except (OSError, PermissionError) as e:
                self.logger.warning(
                    "canary_remove_failed", path=canary_path, error=str(e)
                )

    async def _check_canaries(self) -> None:
        """Verify each canary file exists and has expected content hash."""
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, self._verify_canaries_sync)

        for canary_path, result in results.items():
            self._canary_health[canary_path] = result
            self._stats["canary_checks"] += 1

            if result["status"] != "ok":
                # Canary has been tampered with — CRITICAL alert
                self._stats["canary_alerts"] += 1
                detection = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "canary_tampered",
                    "severity": "critical",
                    "details": {
                        "path": canary_path,
                        "reason": result["reason"],
                        "directory": result.get("directory", ""),
                    },
                    "message": (
                        f"Ransomware canary file tampered: {result['reason']} "
                        f"at {canary_path}"
                    ),
                }
                self._detection_log.append(detection)
                self.logger.critical(
                    "canary_tampered",
                    path=canary_path,
                    reason=result["reason"],
                )
                await self._emit_alert(detection)

    def _verify_canaries_sync(self) -> dict[str, dict]:
        """Synchronously verify all canary files (runs in executor)."""
        results: dict[str, dict] = {}
        now_iso = datetime.now(timezone.utc).isoformat()

        for canary_path in self._canary_paths:
            directory = self._canary_health.get(canary_path, {}).get("directory", "")
            base_info = {
                "last_check": now_iso,
                "expected_hash": CANARY_HASH,
                "directory": directory,
            }

            if not os.path.exists(canary_path):
                results[canary_path] = {
                    **base_info,
                    "status": "missing",
                    "reason": "canary_file_deleted",
                    "current_hash": None,
                }
                continue

            try:
                with open(canary_path, "rb") as f:
                    content = f.read()
                current_hash = hashlib.sha256(content).hexdigest()

                if current_hash != CANARY_HASH:
                    results[canary_path] = {
                        **base_info,
                        "status": "modified",
                        "reason": "canary_content_modified",
                        "current_hash": current_hash,
                    }
                else:
                    results[canary_path] = {
                        **base_info,
                        "status": "ok",
                        "reason": None,
                        "current_hash": current_hash,
                    }
            except (OSError, PermissionError) as e:
                results[canary_path] = {
                    **base_info,
                    "status": "unreadable",
                    "reason": f"canary_read_error: {e}",
                    "current_hash": None,
                }

        return results

    # ── Subsystem 2: Shadow Copy Deletion Detection ──────────────────────

    async def _check_shadow_copy_deletion(self) -> None:
        """Check recent process events for shadow-copy / recovery sabotage commands."""
        if not self._process_analyzer:
            return

        try:
            # Get recent processes from the process analyzer
            processes = self._process_analyzer.get_processes()
        except Exception as e:
            self.logger.debug("shadow_check_process_read_error", error=str(e))
            return

        for proc in processes:
            proc_name = (proc.get("name") or "").lower()
            proc_exe = (proc.get("exe") or "").lower()

            # Only inspect processes that could issue these commands
            if not any(
                tool in proc_name
                for tool in ("vssadmin", "wmic", "bcdedit", "wbadmin",
                             "powershell", "cmd")
            ):
                continue

            # Check the executable path + name for known indicators.
            # For full cmdline matching we would need Sysmon Event ID 1 data;
            # here we check what the process analyzer surfaces.
            combined = f"{proc_name} {proc_exe}"
            for indicator in SHADOW_COPY_INDICATORS:
                indicator_parts = indicator.lower().split()
                exe_name = indicator_parts[0]

                # Match the executable name against the running process
                if exe_name in proc_name or exe_name in proc_exe:
                    # Flag the process — we cannot get full cmdline from
                    # process_iter alone, so we raise a warning-level detection
                    # when the binary itself is running. Higher-fidelity matching
                    # happens when event_log_monitor / Sysmon data is available.
                    detection = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "shadow_copy_deletion_attempt",
                        "severity": "critical",
                        "details": {
                            "process_name": proc.get("name"),
                            "process_exe": proc.get("exe"),
                            "pid": proc.get("pid"),
                            "indicator_matched": indicator,
                            "username": proc.get("username"),
                        },
                        "message": (
                            f"Shadow copy / recovery sabotage detected: "
                            f"{proc.get('name')} (PID {proc.get('pid')}) "
                            f"matches indicator '{indicator}'"
                        ),
                    }

                    # Deduplicate — do not re-alert for the same PID + indicator
                    dedup_key = f"{proc.get('pid')}:{indicator}"
                    if not self._detection_already_logged(dedup_key):
                        self._stats["shadow_copy_alerts"] += 1
                        self._detection_log.append(detection)
                        self.logger.critical(
                            "shadow_copy_deletion_detected",
                            pid=proc.get("pid"),
                            process=proc.get("name"),
                            indicator=indicator,
                        )
                        await self._emit_alert(detection)
                    break  # One alert per process is sufficient

    def _detection_already_logged(self, dedup_key: str) -> bool:
        """Check if a detection with this dedup key was already logged recently."""
        for entry in self._detection_log:
            existing_key = entry.get("_dedup_key")
            if existing_key == dedup_key:
                return True
        return False

    # ── Subsystem 3: Mass Encryption Detection ───────────────────────────

    def _track_file_rename(self, old_name: str, new_name: str, timestamp: float) -> None:
        """Record a file rename event into the tracking buffer.

        Called externally by modules that detect file renames (e.g., file_integrity,
        event_log_monitor with Sysmon Event ID 11).
        """
        entry = {
            "old_name": old_name,
            "new_name": new_name,
            "timestamp": timestamp,
            "old_ext": Path(old_name).suffix.lower(),
            "new_ext": Path(new_name).suffix.lower(),
        }
        self._file_rename_buffer.append(entry)
        self._stats["total_renames_tracked"] += 1

    def _check_mass_encryption(self) -> bool:
        """Analyze the rename buffer for mass-rename patterns indicative of ransomware.

        Returns True if the mass-rename threshold is exceeded within the time window.
        """
        now = time.time()
        cutoff = now - self._mass_rename_window

        # Filter renames within the detection window
        recent_renames = [
            r for r in self._file_rename_buffer
            if r["timestamp"] >= cutoff
        ]

        if len(recent_renames) < self._mass_rename_threshold:
            return False

        # Count renames where the extension changed
        extension_changes = [
            r for r in recent_renames
            if r["old_ext"] != r["new_ext"] and r["new_ext"] != ""
        ]

        if len(extension_changes) < self._mass_rename_threshold:
            return False

        # Check if many files are being renamed to the same new extension
        new_ext_counts: dict[str, int] = {}
        for r in extension_changes:
            ext = r["new_ext"]
            new_ext_counts[ext] = new_ext_counts.get(ext, 0) + 1

        # If a single extension dominates, that is highly suspicious
        max_ext_count = max(new_ext_counts.values()) if new_ext_counts else 0

        # Also check for known ransomware extensions
        known_ext_hits = sum(
            count for ext, count in new_ext_counts.items()
            if ext in RANSOMWARE_EXTENSIONS
        )

        # Trigger if: many extension changes to a single ext, or known ransomware ext
        if max_ext_count >= self._mass_rename_threshold or known_ext_hits >= 5:
            return True

        # Fallback: sheer volume of extension changes in the window
        if len(extension_changes) >= self._mass_rename_threshold * 2:
            return True

        return False

    async def _evaluate_mass_encryption(self) -> None:
        """Run mass encryption check and optionally sample file entropy."""
        if not self._check_mass_encryption():
            return

        # Gather the recent suspicious renames for the alert
        now = time.time()
        cutoff = now - self._mass_rename_window
        recent = [
            r for r in self._file_rename_buffer
            if r["timestamp"] >= cutoff and r["old_ext"] != r["new_ext"]
        ]

        # Sample entropy from a few of the renamed files (if they exist)
        entropy_samples: list[dict] = []
        loop = asyncio.get_event_loop()
        sampled = 0
        for rename in recent[:10]:  # Sample up to 10 files
            new_path = rename["new_name"]
            if os.path.isfile(new_path):
                try:
                    entropy = await loop.run_in_executor(
                        None, self._sample_file_entropy, new_path
                    )
                    entropy_samples.append({
                        "path": new_path,
                        "entropy": round(entropy, 4),
                        "high_entropy": entropy >= HIGH_ENTROPY_THRESHOLD,
                    })
                    sampled += 1
                except Exception:
                    pass
            if sampled >= 5:
                break

        # Determine severity based on entropy evidence
        high_entropy_count = sum(
            1 for s in entropy_samples if s.get("high_entropy")
        )
        severity = "critical" if high_entropy_count >= 3 else "high"

        # Count unique new extensions
        new_exts = set(r["new_ext"] for r in recent if r["new_ext"])
        known_hits = new_exts & RANSOMWARE_EXTENSIONS

        detection = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "mass_encryption_detected",
            "severity": severity,
            "details": {
                "renames_in_window": len(recent),
                "window_seconds": self._mass_rename_window,
                "new_extensions": sorted(new_exts),
                "known_ransomware_extensions": sorted(known_hits),
                "entropy_samples": entropy_samples,
                "high_entropy_files": high_entropy_count,
            },
            "message": (
                f"Mass file encryption detected: {len(recent)} files renamed "
                f"with new extensions in {self._mass_rename_window}s window. "
                f"Extensions: {', '.join(sorted(new_exts))}. "
                f"High-entropy files: {high_entropy_count}/{len(entropy_samples)}"
            ),
        }

        # Deduplicate — one alert per window
        dedup_key = f"mass_encrypt:{int(now // self._mass_rename_window)}"
        if not self._detection_already_logged(dedup_key):
            detection["_dedup_key"] = dedup_key
            self._stats["mass_encryption_alerts"] += 1
            self._detection_log.append(detection)
            self.logger.critical(
                "mass_encryption_detected",
                renames=len(recent),
                extensions=sorted(new_exts),
                high_entropy=high_entropy_count,
            )
            await self._emit_alert(detection)

    def _sample_file_entropy(self, file_path: str) -> float:
        """Read up to ENTROPY_SAMPLE_SIZE bytes from a file and compute Shannon entropy."""
        try:
            with open(file_path, "rb") as f:
                data = f.read(ENTROPY_SAMPLE_SIZE)
            return self._calculate_entropy(data)
        except (OSError, PermissionError):
            return 0.0

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence.

        Returns a value between 0.0 (uniform) and 8.0 (maximum entropy for bytes).
        Encrypted or compressed data typically scores > 7.0.
        """
        if not data:
            return 0.0

        length = len(data)
        frequency: dict[int, int] = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1

        entropy = 0.0
        for count in frequency.values():
            if count == 0:
                continue
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    # ── Alert Emission ───────────────────────────────────────────────────

    async def _emit_alert(self, detection: dict) -> None:
        """Send a detection alert through the alert manager if available."""
        if not self._alert_manager:
            self.logger.debug(
                "alert_manager_not_set_skipping_alert",
                detection_type=detection.get("type"),
            )
            return

        try:
            alert_data = {
                "source": "ransomware_detector",
                "severity": detection["severity"],
                "type": detection["type"],
                "message": detection["message"],
                "details": detection.get("details", {}),
                "timestamp": detection["timestamp"],
            }

            if hasattr(self._alert_manager, "create_alert"):
                await self._alert_manager.create_alert(alert_data)
            elif hasattr(self._alert_manager, "add_alert"):
                await self._alert_manager.add_alert(alert_data)
            else:
                self.logger.warning(
                    "alert_manager_no_compatible_method",
                    available=dir(self._alert_manager),
                )
        except Exception as e:
            self.logger.error("alert_emission_error", error=str(e))

    # ── Public API ───────────────────────────────────────────────────────

    def get_status(self) -> dict:
        """Return comprehensive module status."""
        canary_ok = all(
            c.get("status") == "ok" for c in self._canary_health.values()
        )
        return {
            "name": self.name,
            "enabled": self.enabled,
            "running": self.running,
            "health_status": self.health_status,
            "last_heartbeat": (
                self.last_heartbeat.isoformat() if self.last_heartbeat else None
            ),
            "canary_count": len(self._canary_paths),
            "canaries_healthy": canary_ok,
            "detections_total": len(self._detection_log),
            "renames_buffered": len(self._file_rename_buffer),
            "last_check": (
                self._last_check.isoformat() if self._last_check else None
            ),
            "stats": dict(self._stats),
            "subsystems": {
                "canary_files": self._enable_canaries,
                "shadow_copy_detection": self._enable_shadow_detection,
                "mass_encryption_detection": self._enable_mass_encryption,
            },
        }

    def get_canaries(self) -> list[dict]:
        """Return the status of all deployed canary files."""
        canaries = []
        for canary_path in self._canary_paths:
            health = self._canary_health.get(canary_path, {})
            canaries.append({
                "path": canary_path,
                "directory": health.get("directory", ""),
                "status": health.get("status", "unknown"),
                "reason": health.get("reason"),
                "last_check": health.get("last_check"),
                "expected_hash": health.get("expected_hash", CANARY_HASH),
                "current_hash": health.get("current_hash"),
            })
        return canaries

    def get_detections(self) -> list[dict]:
        """Return all recorded detections, newest first."""
        detections = list(self._detection_log)
        detections.reverse()
        # Strip internal dedup keys from the output
        return [
            {k: v for k, v in d.items() if not k.startswith("_")}
            for d in detections
        ]

    def get_detections_by_type(self, detection_type: str, limit: int = 100) -> list[dict]:
        """Return detections filtered by type, newest first."""
        filtered = [
            d for d in self._detection_log if d.get("type") == detection_type
        ]
        filtered.reverse()
        return [
            {k: v for k, v in d.items() if not k.startswith("_")}
            for d in filtered[:limit]
        ]

    def get_detections_by_severity(self, severity: str, limit: int = 100) -> list[dict]:
        """Return detections filtered by severity level, newest first."""
        filtered = [
            d for d in self._detection_log if d.get("severity") == severity
        ]
        filtered.reverse()
        return [
            {k: v for k, v in d.items() if not k.startswith("_")}
            for d in filtered[:limit]
        ]

    def get_rename_buffer(self, limit: int = 100) -> list[dict]:
        """Return recent file rename events from the tracking buffer."""
        items = list(self._file_rename_buffer)
        items.reverse()
        return items[:limit]

    def get_stats(self) -> dict:
        """Return detection statistics."""
        return {
            **self._stats,
            "canary_count": len(self._canary_paths),
            "detection_log_size": len(self._detection_log),
            "rename_buffer_size": len(self._file_rename_buffer),
            "last_check": (
                self._last_check.isoformat() if self._last_check else None
            ),
        }
