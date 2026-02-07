"""Tests for ZScoreDetector."""

import numpy as np
import pytest


@pytest.fixture
def detector():
    from backend.ai.zscore_detector import ZScoreDetector
    return ZScoreDetector(model_dir="test_models", threshold=3.0)


def make_normal_data(n=100):
    rng = np.random.RandomState(42)
    return rng.randn(n, 12).astype(np.float32) * 0.5 + 5.0


class TestZScoreDetector:
    def test_update_baseline(self, detector):
        data = make_normal_data()
        stats = detector.update_baseline(data)
        assert stats["samples"] == 100
        assert detector.initialized

    def test_predict_normal(self, detector):
        data = make_normal_data()
        detector.update_baseline(data)

        result = detector.predict(data[0])
        assert "anomaly_score" in result
        assert "is_anomaly" in result
        assert result["is_anomaly"] is False

    def test_predict_outlier(self, detector):
        data = make_normal_data()
        detector.update_baseline(data)

        outlier = np.ones(12, dtype=np.float32) * 100.0
        result = detector.predict(outlier)
        assert result["is_anomaly"] is True
        assert result["anomaly_score"] > 0.3

    def test_predict_without_baseline(self, detector):
        features = np.zeros(12, dtype=np.float32)
        result = detector.predict(features)
        assert result["anomaly_score"] == 0.0
        assert result["is_anomaly"] is False

    def test_per_feature_zscores(self, detector):
        data = make_normal_data()
        detector.update_baseline(data)
        result = detector.predict(data[0])
        assert "per_feature_zscores" in result
        assert len(result["per_feature_zscores"]) == 12

    @pytest.mark.asyncio
    async def test_save_and_load(self, tmp_path):
        from backend.ai.zscore_detector import ZScoreDetector
        det = ZScoreDetector(model_dir=str(tmp_path))
        data = make_normal_data()
        det.update_baseline(data)
        await det.save_baseline()

        det2 = ZScoreDetector(model_dir=str(tmp_path))
        await det2.load_baseline()
        assert det2.initialized
        result = det2.predict(data[0])
        assert "anomaly_score" in result
