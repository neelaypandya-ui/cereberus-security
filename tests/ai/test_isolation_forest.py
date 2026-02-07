"""Tests for IsolationForestDetector."""

import numpy as np
import pytest


@pytest.fixture
def detector():
    from backend.ai.isolation_forest_detector import IsolationForestDetector
    return IsolationForestDetector(model_dir="test_models", contamination=0.1)


def make_normal_data(n=100):
    """Generate normal-looking network feature data."""
    rng = np.random.RandomState(42)
    return rng.randn(n, 12).astype(np.float32) * 0.5 + 5.0


class TestIsolationForestDetector:
    def test_train_returns_stats(self, detector):
        data = make_normal_data()
        stats = detector.train(data)
        assert "samples" in stats
        assert stats["samples"] == 100
        assert "mean_score" in stats

    def test_predict_returns_score(self, detector):
        data = make_normal_data()
        detector.train(data)

        normal = data[0]
        result = detector.predict(normal)
        assert "anomaly_score" in result
        assert "is_anomaly" in result
        assert 0.0 <= result["anomaly_score"] <= 1.0

    def test_anomaly_detected_for_outlier(self, detector):
        data = make_normal_data()
        detector.train(data)

        outlier = np.ones(12, dtype=np.float32) * 100.0
        result = detector.predict(outlier)
        assert result["is_anomaly"] == True
        assert result["anomaly_score"] > 0.3

    def test_predict_without_training(self, detector):
        features = np.zeros(12, dtype=np.float32)
        result = detector.predict(features)
        assert result["anomaly_score"] == 0.0
        assert result["is_anomaly"] is False

    @pytest.mark.asyncio
    async def test_save_and_load(self, detector, tmp_path):
        from backend.ai.isolation_forest_detector import IsolationForestDetector
        det = IsolationForestDetector(model_dir=str(tmp_path))
        data = make_normal_data()
        det.train(data)
        await det.save_model()

        det2 = IsolationForestDetector(model_dir=str(tmp_path))
        await det2.load_model()
        assert det2.initialized
        result = det2.predict(data[0])
        assert "anomaly_score" in result
