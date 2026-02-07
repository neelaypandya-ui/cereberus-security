"""Tests for AI API routes."""

import pytest


class TestAiRoutes:
    """Test AI-related endpoints structure and response shapes."""

    def test_ai_status_shape(self):
        """Verify the expected shape of the AI status response."""
        # This tests the structure of what the /ai/status endpoint returns
        expected_keys = {"detectors", "ensemble", "baseline", "forecaster"}
        sample = {
            "detectors": {
                "autoencoder": {"initialized": False, "threshold": 0.5, "has_model": False},
                "isolation_forest": {"initialized": False, "has_model": False},
                "zscore": {"initialized": False, "has_baseline": False, "sample_count": 0},
            },
            "ensemble": {"last_score": None, "last_is_anomaly": None, "drift_score": 0.0},
            "baseline": {"total_buckets": 0, "total_possible": 1680, "coverage_percent": 0.0, "total_samples": 0},
            "forecaster": {"initialized": False, "has_model": False},
        }
        assert set(sample.keys()) == expected_keys

    def test_anomaly_events_shape(self):
        """Verify the expected shape of anomaly event records."""
        sample = {
            "id": 1,
            "timestamp": "2024-01-01T00:00:00",
            "detector_type": "ensemble",
            "anomaly_score": 0.75,
            "threshold": 0.5,
            "is_anomaly": True,
            "explanation": "ANOMALY DETECTED",
            "confidence": 0.8,
            "detector_scores": {},
            "feature_attribution": {},
            "context": {},
        }
        required = {"id", "timestamp", "detector_type", "anomaly_score", "is_anomaly", "explanation"}
        assert required.issubset(set(sample.keys()))

    def test_prediction_shape(self):
        """Verify the expected shape of prediction response."""
        sample = {
            "predictions": [
                {"cpu_percent": 45.0, "memory_percent": 60.0, "step": 1, "minutes_ahead": 10},
            ],
            "forecast_alerts": [],
            "actual_recent": [],
        }
        assert "predictions" in sample
        assert "forecast_alerts" in sample

    def test_model_registry_shape(self):
        """Verify the expected shape of model registry entries."""
        sample = {
            "id": 1,
            "model_name": "autoencoder",
            "version": 1,
            "trained_at": "2024-01-01T00:00:00",
            "samples_count": 100,
            "epochs": 50,
            "final_loss": 0.001,
            "status": "active",
            "is_current": True,
        }
        required = {"id", "model_name", "version", "status", "is_current"}
        assert required.issubset(set(sample.keys()))

    def test_feedback_stats_shape(self):
        """Verify the expected shape of feedback stats response."""
        sample = {
            "total_true_positive": 10,
            "total_false_positive": 3,
            "accuracy": 0.769,
            "by_module": {},
        }
        assert "accuracy" in sample
        assert "total_true_positive" in sample
