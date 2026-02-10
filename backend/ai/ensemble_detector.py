"""Ensemble Detector — anomaly detection using autoencoder with explainability.

Simplified from triple-detector (autoencoder + isolation forest + z-score) to
single-detector since the behavioral baseline already provides z-score coverage.
"""

from typing import Optional

import numpy as np

from ..utils.logging import get_logger

logger = get_logger("ai.ensemble_detector")


class EnsembleDetector:
    """Anomaly detection using autoencoder with explainability."""

    def __init__(
        self,
        autoencoder=None,
        **_kwargs,
    ):
        self._autoencoder = autoencoder
        self._last_result: Optional[dict] = None
        self._score_history: list[float] = []
        self._max_history: int = 100
        self._explainer = None

        try:
            from .explainability import AnomalyExplainer
            self._explainer = AnomalyExplainer()
        except ImportError:
            pass

    def set_detectors(self, autoencoder=None, **_kwargs) -> None:
        """Attach detector instances."""
        if autoencoder is not None:
            self._autoencoder = autoencoder

    async def predict(self, features: np.ndarray) -> dict:
        """Run autoencoder and return anomaly result.

        Args:
            features: 1D numpy array of features.

        Returns:
            Dict with ensemble_score, is_anomaly, detector_scores,
            agreeing_detectors, confidence.
        """
        detector_scores = {}
        detector_anomalies = {}

        if self._autoencoder and self._autoencoder.initialized:
            try:
                result = await self._autoencoder.predict(features)
                detector_scores["autoencoder"] = result["anomaly_score"]
                detector_anomalies["autoencoder"] = result["is_anomaly"]
            except Exception as e:
                logger.error("autoencoder_predict_error", error=str(e))

        if not detector_scores:
            return {
                "ensemble_score": 0.0,
                "is_anomaly": False,
                "detector_scores": {},
                "agreeing_detectors": [],
                "confidence": 0.0,
            }

        ensemble_score = float(np.clip(detector_scores.get("autoencoder", 0.0), 0.0, 1.0))
        is_anomaly = detector_anomalies.get("autoencoder", False)
        agreeing = [k for k, v in detector_anomalies.items() if v]
        confidence = ensemble_score if is_anomaly else 1.0 - ensemble_score

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
                    "ensemble_score": ensemble_score,
                    "is_anomaly": is_anomaly,
                    "agreeing_detectors": agreeing,
                }
                explanation = self._explainer.generate_explanation(attribution, detector_scores, result_for_explain)
                confidence = self._explainer.compute_confidence(detector_scores, len(agreeing))
            except Exception as e:
                logger.error("explainability_error", error=str(e))

        self._last_result = {
            "ensemble_score": ensemble_score,
            "is_anomaly": is_anomaly,
            "detector_scores": detector_scores,
            "agreeing_detectors": agreeing,
            "confidence": float(confidence),
            "feature_attribution": attribution,
            "explanation": explanation,
        }

        self._score_history.append(ensemble_score)
        if len(self._score_history) > self._max_history:
            self._score_history = self._score_history[-self._max_history:]

        if is_anomaly:
            logger.warning(
                "anomaly_detected",
                score=ensemble_score,
                confidence=confidence,
            )

        return self._last_result

    def reset_score_history(self) -> None:
        """Clear score history — call after retraining."""
        self._score_history.clear()
        logger.info("score_history_reset", reason="model_retrained")

    def get_last_result(self) -> Optional[dict]:
        """Return the most recent result."""
        return self._last_result

    def get_drift_score(self) -> float:
        """Estimate model drift from score volatility."""
        if len(self._score_history) < 20:
            return 0.0
        recent = np.array(self._score_history[-100:])
        std = float(np.std(recent))
        return float(np.clip(std / 0.50, 0.0, 1.0))
