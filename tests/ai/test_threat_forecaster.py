"""Tests for ThreatForecaster."""

import numpy as np
import pytest

from backend.ai.threat_forecaster import ThreatForecaster, SEQUENCE_LENGTH, FEATURE_NAMES


def make_snapshots(n=50):
    """Generate synthetic resource snapshots."""
    rng = np.random.RandomState(42)
    snapshots = []
    for i in range(n):
        snapshots.append({
            "cpu_percent": 30.0 + rng.randn() * 5,
            "memory_percent": 50.0 + rng.randn() * 3,
            "disk_percent": 60.0 + rng.randn() * 1,
            "net_bytes_sent": 1000000 + rng.randint(0, 100000),
            "net_bytes_recv": 2000000 + rng.randint(0, 200000),
        })
    return snapshots


class TestThreatForecaster:
    @pytest.mark.asyncio
    async def test_initialize(self):
        forecaster = ThreatForecaster(model_dir="test_models")
        await forecaster.initialize()
        assert forecaster.initialized
        assert forecaster.model is not None

    @pytest.mark.asyncio
    async def test_train(self):
        forecaster = ThreatForecaster(model_dir="test_models")
        await forecaster.initialize()
        snapshots = make_snapshots(50)
        stats = forecaster.await_train = await forecaster.train(snapshots, epochs=5)
        assert "final_loss" in stats
        assert "samples" in stats
        assert stats["epochs"] == 5

    @pytest.mark.asyncio
    async def test_train_insufficient_data(self):
        forecaster = ThreatForecaster(model_dir="test_models")
        await forecaster.initialize()
        snapshots = make_snapshots(10)  # Less than SEQUENCE_LENGTH + 1
        stats = await forecaster.train(snapshots, epochs=5)
        assert "error" in stats

    @pytest.mark.asyncio
    async def test_predict_next(self):
        forecaster = ThreatForecaster(model_dir="test_models")
        await forecaster.initialize()
        snapshots = make_snapshots(50)
        await forecaster.train(snapshots, epochs=5)

        prediction = await forecaster.predict_next(snapshots[-SEQUENCE_LENGTH:])
        assert len(prediction) == len(FEATURE_NAMES)
        for name in FEATURE_NAMES:
            assert name in prediction

    @pytest.mark.asyncio
    async def test_predict_trend(self):
        forecaster = ThreatForecaster(model_dir="test_models")
        await forecaster.initialize()
        snapshots = make_snapshots(50)
        await forecaster.train(snapshots, epochs=5)

        trend = await forecaster.predict_trend(snapshots, steps=6)
        assert len(trend) == 6
        for pred in trend:
            assert "step" in pred
            assert "minutes_ahead" in pred
            assert "cpu_percent" in pred

    @pytest.mark.asyncio
    async def test_predict_without_training(self):
        forecaster = ThreatForecaster(model_dir="test_models")
        await forecaster.initialize()
        snapshots = make_snapshots(SEQUENCE_LENGTH)
        result = await forecaster.predict_next(snapshots)
        # Should still return something (untrained model)
        assert isinstance(result, dict)

    def test_check_forecast_alerts(self):
        forecaster = ThreatForecaster()
        predictions = [
            {"cpu_percent": 95.0, "memory_percent": 50.0, "disk_percent": 60.0, "minutes_ahead": 10, "step": 1},
            {"cpu_percent": 50.0, "memory_percent": 90.0, "disk_percent": 60.0, "minutes_ahead": 20, "step": 2},
        ]
        alerts = forecaster.check_forecast_alerts(predictions)
        assert len(alerts) == 2
        assert alerts[0]["metric"] == "cpu_percent"
        assert alerts[1]["metric"] == "memory_percent"

    def test_check_forecast_alerts_none(self):
        forecaster = ThreatForecaster()
        predictions = [
            {"cpu_percent": 50.0, "memory_percent": 50.0, "disk_percent": 60.0, "minutes_ahead": 10, "step": 1},
        ]
        alerts = forecaster.check_forecast_alerts(predictions)
        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_save_and_load(self, tmp_path):
        forecaster = ThreatForecaster(model_dir=str(tmp_path))
        await forecaster.initialize()
        snapshots = make_snapshots(50)
        await forecaster.train(snapshots, epochs=5)
        await forecaster.save_model()

        forecaster2 = ThreatForecaster(model_dir=str(tmp_path))
        await forecaster2.initialize()
        assert forecaster2.initialized
        prediction = await forecaster2.predict_next(snapshots[-SEQUENCE_LENGTH:])
        assert len(prediction) > 0
