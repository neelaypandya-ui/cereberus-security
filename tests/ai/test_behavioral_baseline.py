"""Tests for BehavioralBaselineEngine."""

from datetime import datetime, timezone

import pytest

from backend.ai.behavioral_baseline import BehavioralBaselineEngine


@pytest.fixture
def engine():
    return BehavioralBaselineEngine()


class TestBehavioralBaselineEngine:
    @pytest.mark.asyncio
    async def test_update_creates_bucket(self, engine):
        ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)  # Monday hour 10
        await engine.update("cpu_percent", 50.0, ts)
        assert engine.total_buckets == 1
        assert engine.total_samples == 1

    @pytest.mark.asyncio
    async def test_multiple_updates_same_bucket(self, engine):
        ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        await engine.update("cpu_percent", 50.0, ts)
        await engine.update("cpu_percent", 60.0, ts)
        await engine.update("cpu_percent", 55.0, ts)
        assert engine.total_buckets == 1
        assert engine.total_samples == 3

    @pytest.mark.asyncio
    async def test_different_hours_separate_buckets(self, engine):
        ts1 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc)
        await engine.update("cpu_percent", 50.0, ts1)
        await engine.update("cpu_percent", 70.0, ts2)
        assert engine.total_buckets == 2

    @pytest.mark.asyncio
    async def test_deviation_score_normal(self, engine):
        ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        for v in [50.0, 52.0, 48.0, 51.0, 49.0]:
            await engine.update("cpu_percent", v, ts)

        result = engine.get_deviation_score("cpu_percent", 50.5, ts)
        assert result["is_deviation"] is False
        assert result["z_score"] < 3.0

    @pytest.mark.asyncio
    async def test_deviation_score_outlier(self, engine):
        ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        for v in [50.0, 52.0, 48.0, 51.0, 49.0]:
            await engine.update("cpu_percent", v, ts)

        result = engine.get_deviation_score("cpu_percent", 200.0, ts)
        assert result["is_deviation"] is True
        assert result["z_score"] > 3.0

    @pytest.mark.asyncio
    async def test_deviation_score_no_data(self, engine):
        ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = engine.get_deviation_score("cpu_percent", 50.0, ts)
        assert result["is_deviation"] is False
        assert result["z_score"] == 0.0

    @pytest.mark.asyncio
    async def test_bulk_update_from_snapshots(self, engine):
        snapshots = [
            {
                "timestamp": "2024-01-15T10:00:00+00:00",
                "cpu_percent": 50.0,
                "memory_percent": 60.0,
                "disk_percent": 70.0,
                "net_bytes_sent": 1000,
                "net_bytes_recv": 2000,
            },
            {
                "timestamp": "2024-01-15T10:05:00+00:00",
                "cpu_percent": 55.0,
                "memory_percent": 62.0,
                "disk_percent": 70.0,
                "net_bytes_sent": 1100,
                "net_bytes_recv": 2100,
            },
        ]
        result = await engine.bulk_update_from_snapshots(snapshots)
        assert result["metrics_updated"] == 10  # 5 metrics * 2 snapshots
        assert result["total_buckets"] > 0

    def test_get_all_baselines(self, engine):
        result = engine.get_all_baselines()
        assert isinstance(result, list)

    def test_get_learning_progress(self, engine):
        result = engine.get_learning_progress()
        assert "total_buckets" in result
        assert "total_possible" in result
        assert "coverage_percent" in result
        assert result["total_possible"] == 10 * 24 * 7  # 10 metrics * 24h * 7 days
