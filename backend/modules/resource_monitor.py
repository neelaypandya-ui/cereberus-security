"""Resource Monitor Module — tracks system CPU, memory, disk, and network I/O.

Polls psutil metrics at a configurable interval, stores snapshots in a rolling
buffer, and triggers alerts when thresholds are breached.
"""

import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import psutil

from .base_module import BaseModule


class ResourceMonitor(BaseModule):
    """Monitors system resource utilization and alerts on threshold breaches."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="resource_monitor", config=config)

        cfg = config or {}
        self._poll_interval: int = cfg.get("poll_interval", 10)
        self._cpu_threshold: float = cfg.get("cpu_threshold", 90.0)
        self._memory_threshold: float = cfg.get("memory_threshold", 85.0)
        self._disk_threshold: float = cfg.get("disk_threshold", 90.0)

        # Rolling history — 360 samples = 1 hour at 10s intervals
        self._snapshot_history: deque[dict] = deque(maxlen=360)
        self._current: Optional[dict] = None
        self._alerts: list[dict] = []
        self._alert_manager = None
        self._behavioral_baseline = None
        self._poll_task: Optional[asyncio.Task] = None

    def set_alert_manager(self, manager) -> None:
        """Attach the alert manager for threshold breach notifications."""
        self._alert_manager = manager

    def set_behavioral_baseline(self, engine) -> None:
        """Attach the behavioral baseline engine for metric learning."""
        self._behavioral_baseline = engine
        self.logger.info("behavioral_baseline_attached")

    async def start(self) -> None:
        self.running = True
        self.health_status = "running"
        self.logger.info("resource_monitor_starting")

        # Initial snapshot
        await self._take_snapshot()

        self._poll_task = asyncio.create_task(self._poll_loop())
        self.heartbeat()
        self.logger.info("resource_monitor_started")

    async def stop(self) -> None:
        self.running = False
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        self.health_status = "stopped"
        self.logger.info("resource_monitor_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "snapshots": len(self._snapshot_history),
                "current_cpu": self._current.get("cpu_percent") if self._current else None,
                "current_memory": self._current.get("memory_percent") if self._current else None,
                "alerts_count": len(self._alerts),
            },
        }

    async def _poll_loop(self) -> None:
        while self.running:
            try:
                await asyncio.sleep(self._poll_interval)
                if self.running:
                    await self._take_snapshot()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("resource_snapshot_error", error=str(e))
                await asyncio.sleep(self._poll_interval)

    async def _take_snapshot(self) -> None:
        loop = asyncio.get_event_loop()
        snapshot = await loop.run_in_executor(None, self._collect_metrics)
        self._current = snapshot
        self._snapshot_history.append(snapshot)
        self._check_thresholds(snapshot)

        # Feed behavioral baseline engine
        if self._behavioral_baseline:
            try:
                from datetime import datetime, timezone
                ts = datetime.now(timezone.utc)
                for metric in ("cpu_percent", "memory_percent", "disk_percent", "net_bytes_sent", "net_bytes_recv"):
                    val = snapshot.get(metric)
                    if val is not None:
                        await self._behavioral_baseline.update(metric, float(val), ts)
            except Exception as e:
                self.logger.error("baseline_update_error", error=str(e))

        self.heartbeat()

    def _collect_metrics(self) -> dict:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        try:
            disk = psutil.disk_usage("C:\\")
        except Exception:
            disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu_percent": cpu,
            "memory_percent": mem.percent,
            "memory_used_gb": round(mem.used / (1024 ** 3), 2),
            "memory_total_gb": round(mem.total / (1024 ** 3), 2),
            "disk_percent": disk.percent,
            "disk_used_gb": round(disk.used / (1024 ** 3), 2),
            "disk_total_gb": round(disk.total / (1024 ** 3), 2),
            "net_bytes_sent": net.bytes_sent,
            "net_bytes_recv": net.bytes_recv,
            "alert_triggered": False,
        }

    def _check_thresholds(self, snapshot: dict) -> None:
        breaches = []
        if snapshot["cpu_percent"] >= self._cpu_threshold:
            breaches.append(f"CPU at {snapshot['cpu_percent']}% (threshold: {self._cpu_threshold}%)")
        if snapshot["memory_percent"] >= self._memory_threshold:
            breaches.append(f"Memory at {snapshot['memory_percent']}% (threshold: {self._memory_threshold}%)")
        if snapshot["disk_percent"] >= self._disk_threshold:
            breaches.append(f"Disk at {snapshot['disk_percent']}% (threshold: {self._disk_threshold}%)")

        if breaches:
            snapshot["alert_triggered"] = True
            alert = {
                "timestamp": snapshot["timestamp"],
                "breaches": breaches,
                "cpu": snapshot["cpu_percent"],
                "memory": snapshot["memory_percent"],
                "disk": snapshot["disk_percent"],
            }
            self._alerts.append(alert)
            # Keep last 100 alerts
            if len(self._alerts) > 100:
                self._alerts = self._alerts[-100:]
            self.logger.warning("resource_threshold_breach", breaches=breaches)

    # --- Public API ---

    def get_current(self) -> dict:
        return self._current or {}

    def get_history(self, limit: int = 60) -> list[dict]:
        history = list(self._snapshot_history)
        return history[-limit:]

    def get_alerts(self) -> list[dict]:
        return self._alerts
