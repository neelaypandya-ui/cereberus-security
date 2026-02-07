"""Isolation Forest Detector — sklearn-based anomaly detection.

Uses the same 12-feature space as the autoencoder AnomalyDetector
but applies Isolation Forest for complementary detection.
"""

import asyncio
from pathlib import Path
from typing import Optional

import numpy as np

from ..utils.logging import get_logger

logger = get_logger("ai.isolation_forest")


class IsolationForestDetector:
    """Anomaly detection via sklearn IsolationForest."""

    def __init__(self, model_dir: Optional[str] = None, contamination: float = 0.05):
        self.model_dir = Path(model_dir) if model_dir else Path("models")
        self.model_path = self.model_dir / "isolation_forest.joblib"
        self.contamination = contamination
        self._model = None
        self.initialized = False
        self._feature_mean: Optional[np.ndarray] = None
        self._feature_std: Optional[np.ndarray] = None

    async def initialize(self) -> None:
        """Load model from disk if available."""
        if self.model_path.exists():
            await self.load_model()
        self.initialized = True

    def train(self, feature_matrix: np.ndarray) -> dict:
        """Train Isolation Forest on a feature matrix (N x 12).

        Args:
            feature_matrix: 2D array of shape (n_samples, n_features).

        Returns:
            Training stats dict.
        """
        from sklearn.ensemble import IsolationForest

        self._feature_mean = feature_matrix.mean(axis=0)
        self._feature_std = feature_matrix.std(axis=0)
        self._feature_std[self._feature_std == 0] = 1.0

        normalized = (feature_matrix - self._feature_mean) / self._feature_std

        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self._model.fit(normalized)
        self.initialized = True

        scores = self._model.decision_function(normalized)
        return {
            "samples": len(feature_matrix),
            "mean_score": float(scores.mean()),
            "contamination": self.contamination,
        }

    def predict(self, features: np.ndarray) -> dict:
        """Run anomaly detection on a single feature vector.

        Args:
            features: 1D array of features.

        Returns:
            Dict with anomaly_score (0-1), is_anomaly.
        """
        if self._model is None:
            return {"anomaly_score": 0.0, "is_anomaly": False}

        if features.ndim == 1:
            features = features.reshape(1, -1)

        normalized = self._normalize(features)
        raw_score = self._model.decision_function(normalized)[0]
        prediction = self._model.predict(normalized)[0]

        # Convert sklearn score to 0-1 range (lower decision_function = more anomalous)
        # Typical range is roughly -0.5 to 0.5; we map to 0-1
        anomaly_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))

        return {
            "anomaly_score": anomaly_score,
            "is_anomaly": prediction == -1,
        }

    def _normalize(self, features: np.ndarray) -> np.ndarray:
        if self._feature_mean is not None and self._feature_std is not None:
            return (features - self._feature_mean) / self._feature_std
        return features

    async def save_model(self) -> None:
        """Save model to disk via joblib."""
        if self._model is None:
            return
        import joblib
        self.model_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "model": self._model,
            "feature_mean": self._feature_mean,
            "feature_std": self._feature_std,
        }
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: joblib.dump(state, self.model_path))
        logger.info("isolation_forest_saved", path=str(self.model_path))

    async def load_model(self) -> None:
        """Load model from disk via joblib."""
        if not self.model_path.exists():
            return
        import joblib
        loop = asyncio.get_event_loop()
        state = await loop.run_in_executor(None, lambda: joblib.load(self.model_path))
        self._model = state["model"]
        self._feature_mean = state.get("feature_mean")
        self._feature_std = state.get("feature_std")
        self.initialized = True
        logger.info("isolation_forest_loaded", path=str(self.model_path))
