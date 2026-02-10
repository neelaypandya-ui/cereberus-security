"""Tests for EnsembleDetector."""

import numpy as np
import pytest

from backend.ai.anomaly_detector import AnomalyDetector
from backend.ai.ensemble_detector import EnsembleDetector


def make_normal_data(n=100):
    rng = np.random.RandomState(42)
    return rng.randn(n, 12).astype(np.float32) * 0.5 + 5.0


@pytest.fixture
def trained_autoencoder():
    data = make_normal_data()
    connections = []
    for row in data:
        connections.append([{
            "local_port": 80,
            "remote_addr": "1.2.3.4",
            "remote_port": 443,
            "protocol": "tcp",
            "status": "established",
            "suspicious": False,
        }])

    ae = AnomalyDetector(model_dir="test_models", threshold=0.5)
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(ae.initialize())
    finally:
        loop.close()

    return ae


class TestEnsembleDetector:
    @pytest.mark.asyncio
    async def test_predict_returns_all_fields(self, trained_autoencoder):
        ensemble = EnsembleDetector(autoencoder=trained_autoencoder)
        features = make_normal_data(1)[0]
        result = await ensemble.predict(features)

        assert "ensemble_score" in result
        assert "is_anomaly" in result
        assert "detector_scores" in result
        assert "agreeing_detectors" in result
        assert "confidence" in result

    @pytest.mark.asyncio
    async def test_normal_data_not_anomalous(self, trained_autoencoder):
        ensemble = EnsembleDetector(autoencoder=trained_autoencoder)
        features = make_normal_data(1)[0]
        result = await ensemble.predict(features)
        assert result["ensemble_score"] < 0.8

    @pytest.mark.asyncio
    async def test_empty_detectors(self):
        ensemble = EnsembleDetector()
        features = np.zeros(12, dtype=np.float32)
        result = await ensemble.predict(features)
        assert result["ensemble_score"] == 0.0
        assert result["is_anomaly"] is False

    @pytest.mark.asyncio
    async def test_drift_score(self, trained_autoencoder):
        ensemble = EnsembleDetector(autoencoder=trained_autoencoder)
        features = make_normal_data(1)[0]
        await ensemble.predict(features)
        drift = ensemble.get_drift_score()
        assert 0.0 <= drift <= 1.0

    @pytest.mark.asyncio
    async def test_get_last_result(self, trained_autoencoder):
        ensemble = EnsembleDetector(autoencoder=trained_autoencoder)
        assert ensemble.get_last_result() is None
        features = make_normal_data(1)[0]
        await ensemble.predict(features)
        assert ensemble.get_last_result() is not None
