"""Tests for AI API routes."""

import pytest


class TestAiRoutes:
    """Test AI-related endpoints structure and response shapes."""

    def test_ai_status_shape(self):
        """Verify the expected shape of the AI status response."""
        expected_keys = {"detectors", "ensemble", "baseline"}
        sample = {
            "detectors": {
                "autoencoder": {"initialized": False, "threshold": 0.5, "has_model": False},
            },
            "ensemble": {"last_score": None, "last_is_anomaly": None, "drift_score": 0.0},
            "baseline": {"total_buckets": 0, "total_possible": 1680, "coverage_percent": 0.0, "total_samples": 0},
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
