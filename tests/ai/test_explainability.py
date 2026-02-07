"""Tests for AnomalyExplainer."""

import numpy as np
import pytest

from backend.ai.explainability import AnomalyExplainer, FEATURE_NAMES


@pytest.fixture
def explainer():
    return AnomalyExplainer()


class TestAnomalyExplainer:
    def test_compute_attribution_with_baseline(self, explainer):
        features = np.array([10, 0.8, 0.1, 0.05, 0.02, 0.9, 0.1, 0.3, 5, 3, 8, 2], dtype=np.float32)
        baseline_mean = np.array([5, 0.5, 0.15, 0.05, 0.02, 0.85, 0.15, 0.05, 4, 3, 6, 1.5], dtype=np.float32)
        baseline_std = np.array([2, 0.1, 0.05, 0.02, 0.01, 0.05, 0.05, 0.03, 1, 1, 2, 0.5], dtype=np.float32)

        attribution = explainer.compute_attribution(features, baseline_mean, baseline_std)
        assert len(attribution) == len(FEATURE_NAMES)
        assert abs(sum(attribution.values()) - 1.0) < 0.01  # Should sum to ~1
        # suspicious_ratio should be high contributor (0.3 vs 0.05 baseline)
        assert attribution["suspicious_ratio"] > 0.05

    def test_compute_attribution_no_baseline(self, explainer):
        features = np.zeros(12, dtype=np.float32)
        attribution = explainer.compute_attribution(features, None, None)
        assert len(attribution) == len(FEATURE_NAMES)
        # Equal attribution without baseline
        for val in attribution.values():
            assert abs(val - 1.0 / 12) < 0.001

    def test_generate_explanation_anomaly(self, explainer):
        attribution = {name: 1.0 / 12 for name in FEATURE_NAMES}
        attribution["suspicious_ratio"] = 0.5
        detector_scores = {"autoencoder": 0.8, "isolation_forest": 0.7, "zscore": 0.6}
        ensemble_result = {
            "ensemble_score": 0.75,
            "is_anomaly": True,
            "agreeing_detectors": ["autoencoder", "isolation_forest", "zscore"],
        }

        explanation = explainer.generate_explanation(attribution, detector_scores, ensemble_result)
        assert "ANOMALY DETECTED" in explanation
        assert "suspicious" in explanation.lower()

    def test_generate_explanation_normal(self, explainer):
        attribution = {name: 1.0 / 12 for name in FEATURE_NAMES}
        detector_scores = {"autoencoder": 0.1}
        ensemble_result = {
            "ensemble_score": 0.1,
            "is_anomaly": False,
            "agreeing_detectors": [],
        }

        explanation = explainer.generate_explanation(attribution, detector_scores, ensemble_result)
        assert "Normal activity" in explanation

    def test_compute_confidence(self, explainer):
        detector_scores = {"autoencoder": 0.8, "isolation_forest": 0.7, "zscore": 0.6}
        confidence = explainer.compute_confidence(detector_scores, 3)
        assert 0.0 <= confidence <= 1.0
        assert confidence > 0.5  # High agreement should yield high confidence

    def test_compute_confidence_no_agreement(self, explainer):
        detector_scores = {"autoencoder": 0.1, "isolation_forest": 0.9, "zscore": 0.5}
        confidence = explainer.compute_confidence(detector_scores, 0)
        assert 0.0 <= confidence <= 1.0

    def test_compute_confidence_empty(self, explainer):
        confidence = explainer.compute_confidence({}, 0)
        assert confidence == 0.0
