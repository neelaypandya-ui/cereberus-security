"""Behavioral Baseline Engine — learns normal patterns per hour/day using Welford's algorithm.

Tracks 10 system metrics bucketed by (metric_name, hour_of_day, day_of_week)
and provides deviation scoring for real-time anomaly detection.
"""

import math
from datetime import datetime, timezone
from typing import Optional

from ..utils.logging import get_logger

logger = get_logger("ai.behavioral_baseline")

METRICS = [
    "cpu_percent",
    "memory_percent",
    "disk_percent",
    "net_bytes_sent",
    "net_bytes_recv",
    "total_connections",
    "established_connections",
    "suspicious_connections",
    "process_count",
    "suspicious_process_count",
    # Phase 12 additions
    "disk_read_bytes_per_sec",
    "disk_write_bytes_per_sec",
    "thread_count",
    "handle_count",
    "outbound_connection_count",
    "dns_query_rate",
]


class _WelfordState:
    """Running mean/std via Welford's online algorithm."""

    __slots__ = ("count", "mean", "m2", "min_val", "max_val")

    def __init__(self, count=0, mean=0.0, m2=0.0, min_val=float("inf"), max_val=float("-inf")):
        self.count = count
        self.mean = mean
        self.m2 = m2
        self.min_val = min_val
        self.max_val = max_val

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2
        self.min_val = min(self.min_val, value)
        self.max_val = max(self.max_val, value)

    @property
    def std(self) -> float:
        if self.count < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.count - 1))


class BehavioralBaselineEngine:
    """Learns normal behavioral patterns and detects deviations."""

    def __init__(self):
        # Key: (metric_name, hour_of_day, day_of_week) -> _WelfordState
        self._baselines: dict[tuple[str, int, int], _WelfordState] = {}
        self._initialized = False

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def total_buckets(self) -> int:
        return len(self._baselines)

    @property
    def total_samples(self) -> int:
        return sum(s.count for s in self._baselines.values())

    async def initialize(self, db_session) -> None:
        """Load existing baselines from the database."""
        from sqlalchemy import select
        from ..models.behavioral_baseline import BehavioralBaseline

        result = await db_session.execute(select(BehavioralBaseline))
        rows = result.scalars().all()

        for row in rows:
            key = (row.metric_name, row.hour_of_day, row.day_of_week)
            # Reconstruct Welford state from stored mean/std/count
            state = _WelfordState(
                count=row.sample_count,
                mean=row.mean,
                m2=row.std ** 2 * max(row.sample_count - 1, 0),
                min_val=row.min_val,
                max_val=row.max_val,
            )
            self._baselines[key] = state

        self._initialized = True
        logger.info("behavioral_baselines_loaded", buckets=len(self._baselines))

    async def update(
        self,
        metric_name: str,
        value: float,
        timestamp: datetime | None = None,
        db_session=None,
    ) -> None:
        """Update the running baseline for a metric at the current time bucket.

        Args:
            metric_name: One of the 10 tracked metrics.
            value: Current metric value.
            timestamp: Optional timestamp (defaults to now UTC).
            db_session: Optional async DB session for persistence.
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        hour = timestamp.hour
        dow = timestamp.weekday()
        key = (metric_name, hour, dow)

        if key not in self._baselines:
            self._baselines[key] = _WelfordState()

        self._baselines[key].update(value)

        # Persist to DB if session provided
        if db_session is not None:
            await self._persist_bucket(key, db_session)

    async def _persist_bucket(self, key: tuple[str, int, int], db_session) -> None:
        """Upsert a single baseline bucket to the database."""
        from sqlalchemy import select
        from ..models.behavioral_baseline import BehavioralBaseline

        metric_name, hour, dow = key
        state = self._baselines[key]

        result = await db_session.execute(
            select(BehavioralBaseline).where(
                BehavioralBaseline.metric_name == metric_name,
                BehavioralBaseline.hour_of_day == hour,
                BehavioralBaseline.day_of_week == dow,
            )
        )
        row = result.scalar_one_or_none()

        if row is None:
            row = BehavioralBaseline(
                metric_name=metric_name,
                hour_of_day=hour,
                day_of_week=dow,
            )
            db_session.add(row)

        row.mean = state.mean
        row.std = state.std
        row.sample_count = state.count
        row.min_val = state.min_val if state.min_val != float("inf") else 0.0
        row.max_val = state.max_val if state.max_val != float("-inf") else 0.0

        await db_session.commit()

    def get_deviation_score(
        self,
        metric_name: str,
        value: float,
        timestamp: datetime | None = None,
    ) -> dict:
        """Compute how far a value deviates from its baseline.

        Returns:
            Dict with z_score, expected_mean, expected_std, is_deviation.
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        hour = timestamp.hour
        dow = timestamp.weekday()
        key = (metric_name, hour, dow)

        state = self._baselines.get(key)
        if state is None or state.count < 3:
            return {
                "z_score": 0.0,
                "expected_mean": 0.0,
                "expected_std": 0.0,
                "is_deviation": False,
            }

        std = state.std if state.std > 0 else 1.0
        z_score = abs(value - state.mean) / std

        return {
            "z_score": float(z_score),
            "expected_mean": float(state.mean),
            "expected_std": float(state.std),
            "is_deviation": z_score > 3.0,
        }

    async def bulk_update_from_snapshots(self, snapshots: list[dict], db_session=None) -> dict:
        """Bootstrap baselines from historical resource snapshots.

        Args:
            snapshots: List of resource snapshot dicts with timestamp and metric fields.
            db_session: Optional DB session for persistence.

        Returns:
            Stats dict.
        """
        count = 0
        for snap in snapshots:
            ts_str = snap.get("timestamp")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            metric_map = {
                "cpu_percent": snap.get("cpu_percent"),
                "memory_percent": snap.get("memory_percent"),
                "disk_percent": snap.get("disk_percent"),
                "net_bytes_sent": snap.get("net_bytes_sent"),
                "net_bytes_recv": snap.get("net_bytes_recv"),
            }

            for metric_name, value in metric_map.items():
                if value is not None:
                    await self.update(metric_name, float(value), ts)
                    count += 1

        # Persist all if session provided
        if db_session is not None:
            for key in self._baselines:
                await self._persist_bucket(key, db_session)

        return {"metrics_updated": count, "total_buckets": len(self._baselines)}

    def get_all_baselines(self) -> list[dict]:
        """Return all baselines as a list of dicts grouped by metric."""
        result = []
        for (metric, hour, dow), state in sorted(self._baselines.items()):
            result.append({
                "metric_name": metric,
                "hour_of_day": hour,
                "day_of_week": dow,
                "mean": state.mean,
                "std": state.std,
                "sample_count": state.count,
                "min_val": state.min_val if state.min_val != float("inf") else 0.0,
                "max_val": state.max_val if state.max_val != float("-inf") else 0.0,
            })
        return result

    def get_learning_progress(self) -> dict:
        """Return baseline learning progress stats."""
        total_possible = len(METRICS) * 24 * 7  # 10 metrics * 24 hours * 7 days
        filled = len(self._baselines)
        return {
            "total_buckets": filled,
            "total_possible": total_possible,
            "coverage_percent": round(filled / max(total_possible, 1) * 100, 1),
            "total_samples": self.total_samples,
        }
