"""Ensemble Detector — orchestrates multiple anomaly detectors with weighted voting.

Combines AnomalyDetector (autoencoder), IsolationForestDetector, and ZScoreDetector
using configurable weights and consensus voting.
"""

from typing import Optional

import numpy as np

from ..utils.logging import get_logger

logger = get_logger("ai.ensemble_detector")


class EnsembleDetector:
    """Orchestrates 3 anomaly detectors with weighted consensus voting."""

    def __init__(
        self,
        autoencoder=None,
        isolation_forest=None,
        zscore=None,
        weights: list[float] | None = None,
        consensus_threshold: int = 2,
    ):
        self._autoencoder = autoencoder
        self._isolation_forest = isolation_forest
        self._zscore = zscore
        self._weights = weights or [0.4, 0.35, 0.25]
        self._consensus_threshold = consensus_threshold
        self._last_result: Optional[dict] = None
        self._score_history: list[float] = []  # Recent ensemble scores for drift detection
        self._max_history: int = 100
        self._explainer = None

        # Lazy import explainer
        try:
            from .explainability import AnomalyExplainer
            self._explainer = AnomalyExplainer()
        except ImportError:
            pass

    def set_detectors(self, autoencoder=None, isolation_forest=None, zscore=None) -> None:
        """Attach detector instances."""
        if autoencoder is not None:
            self._autoencoder = autoencoder
        if isolation_forest is not None:
            self._isolation_forest = isolation_forest
        if zscore is not None:
            self._zscore = zscore

    async def predict(self, features: np.ndarray) -> dict:
        """Run all detectors and combine results.

        Args:
            features: 1D numpy array of features.

        Returns:
            Dict with ensemble_score, is_anomaly, detector_scores,
            agreeing_detectors, confidence.
        """
        detector_scores = {}
        detector_anomalies = {}

        # Autoencoder
        if self._autoencoder and self._autoencoder.initialized:
            try:
                result = await self._autoencoder.predict(features)
                detector_scores["autoencoder"] = result["anomaly_score"]
                detector_anomalies["autoencoder"] = result["is_anomaly"]
            except Exception as e:
                logger.error("autoencoder_predict_error", error=str(e))

        # Isolation Forest
        if self._isolation_forest and self._isolation_forest.initialized:
            try:
                result = self._isolation_forest.predict(features)
                detector_scores["isolation_forest"] = result["anomaly_score"]
                detector_anomalies["isolation_forest"] = result["is_anomaly"]
            except Exception as e:
                logger.error("isolation_forest_predict_error", error=str(e))

        # Z-Score
        if self._zscore and self._zscore.initialized:
            try:
                result = self._zscore.predict(features)
                detector_scores["zscore"] = result["anomaly_score"]
                detector_anomalies["zscore"] = result["is_anomaly"]
            except Exception as e:
                logger.error("zscore_predict_error", error=str(e))

        if not detector_scores:
            return {
                "ensemble_score": 0.0,
                "is_anomaly": False,
                "detector_scores": {},
                "agreeing_detectors": [],
                "confidence": 0.0,
            }

        # Weighted ensemble score (clamp individual scores to 0-1 range)
        ordered_keys = ["autoencoder", "isolation_forest", "zscore"]
        weighted_sum = 0.0
        weight_total = 0.0
        for i, key in enumerate(ordered_keys):
            if key in detector_scores:
                w = self._weights[i] if i < len(self._weights) else 0.0
                clamped = float(np.clip(detector_scores[key], 0.0, 1.0))
                weighted_sum += clamped * w
                weight_total += w

        ensemble_score = weighted_sum / max(weight_total, 1e-9)

        # Consensus voting
        agreeing = [k for k, v in detector_anomalies.items() if v]
        is_anomaly = len(agreeing) >= self._consensus_threshold

        # Confidence based on agreement level and score magnitude
        active_count = len(detector_anomalies)
        agreement_ratio = len(agreeing) / max(active_count, 1)
        confidence = agreement_ratio * min(ensemble_score * 2, 1.0)

        # Compute explainability if available
        attribution = {}
        explanation = ""
        if self._explainer:
            try:
                baseline_mean = None
                baseline_std = None
                if self._autoencoder:
                    baseline_mean = self._autoencoder._feature_mean
                    baseline_std = self._autoencoder._feature_std
                attribution = self._explainer.compute_attribution(features, baseline_mean, baseline_std)
                result_for_explain = {
                    "ensemble_score": float(ensemble_score),
                    "is_anomaly": is_anomaly,
                    "agreeing_detectors": agreeing,
                }
                explanation = self._explainer.generate_explanation(attribution, detector_scores, result_for_explain)
                confidence = self._explainer.compute_confidence(detector_scores, len(agreeing))
            except Exception as e:
                logger.error("explainability_error", error=str(e))

        self._last_result = {
            "ensemble_score": float(ensemble_score),
            "is_anomaly": is_anomaly,
            "detector_scores": detector_scores,
            "agreeing_detectors": agreeing,
            "confidence": float(confidence),
            "feature_attribution": attribution,
            "explanation": explanation,
        }

        # Track score history for drift detection
        self._score_history.append(float(ensemble_score))
        if len(self._score_history) > self._max_history:
            self._score_history = self._score_history[-self._max_history:]

        if is_anomaly:
            logger.warning(
                "ensemble_anomaly_detected",
                score=ensemble_score,
                agreeing=agreeing,
                confidence=confidence,
            )

        return self._last_result

    def reset_score_history(self) -> None:
        """Clear score history — call after retraining so drift measures only post-training stability."""
        self._score_history.clear()
        logger.info("score_history_reset", reason="model_retrained")

    def get_last_result(self) -> Optional[dict]:
        """Return the most recent ensemble result."""
        return self._last_result

    def get_drift_score(self) -> float:
        """Estimate model drift from ensemble score volatility over time.

        Uses the standard deviation of recent ensemble scores over a
        large window.  On a live system inputs naturally vary, so we
        use a generous divisor (0.30) to avoid false-positive drift
        signals from normal network fluctuation.

        Returns 0.0 when insufficient data or stable, approaches 1.0
        when scores swing wildly between predictions.
        """
        if len(self._score_history) < 20:
            return 0.0  # Need enough history to measure drift reliably

        recent = np.array(self._score_history[-100:])
        std = float(np.std(recent))
        # Ensemble scores are 0-1; on a live system natural fluctuation
        # produces std ~0.05-0.07.  Use 0.50 divisor so normal operation
        # reads ~10-14% and genuine drift pushes past 30%.
        return float(np.clip(std / 0.50, 0.0, 1.0))
