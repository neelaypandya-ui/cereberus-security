"""Z-Score Detector — statistical anomaly detection via per-feature z-scores.

Computes z-scores against a rolling baseline mean/std and flags anomalies
when the max z-score exceeds a threshold.
"""

import asyncio
from pathlib import Path
from typing import Optional

import numpy as np

from ..utils.logging import get_logger

logger = get_logger("ai.zscore_detector")


class ZScoreDetector:
    """Statistical anomaly detection using z-score thresholding."""

    def __init__(self, model_dir: Optional[str] = None, threshold: float = 3.0):
        self.model_dir = Path(model_dir) if model_dir else Path("models")
        self.baseline_path = self.model_dir / "zscore_baseline.npz"
        self.threshold = threshold
        self._mean: Optional[np.ndarray] = None
        self._std: Optional[np.ndarray] = None
        self._count: int = 0
        self.initialized = False

    async def initialize(self) -> None:
        """Load baseline from disk if available."""
        if self.baseline_path.exists():
            await self.load_baseline()
        self.initialized = True

    def update_baseline(self, feature_matrix: np.ndarray) -> dict:
        """Update rolling baseline from a batch of feature vectors.

        Args:
            feature_matrix: 2D array of shape (n_samples, n_features).

        Returns:
            Stats dict.
        """
        self._mean = feature_matrix.mean(axis=0)
        self._std = feature_matrix.std(axis=0)
        self._std[self._std == 0] = 1.0
        self._count = len(feature_matrix)
        self.initialized = True

        return {
            "samples": self._count,
            "mean_range": [float(self._mean.min()), float(self._mean.max())],
        }

    def predict(self, features: np.ndarray) -> dict:
        """Compute anomaly score from z-scores.

        Args:
            features: 1D array of features.

        Returns:
            Dict with anomaly_score (0-1), is_anomaly, per_feature_zscores.
        """
        if self._mean is None or self._std is None:
            return {"anomaly_score": 0.0, "is_anomaly": False, "per_feature_zscores": []}

        z_scores = np.abs((features - self._mean) / self._std)
        max_z = float(z_scores.max())

        # Normalize to 0-1: z=0 -> 0, z=threshold -> 0.5, z=2*threshold -> ~0.75
        anomaly_score = float(np.clip(max_z / (2 * self.threshold), 0.0, 1.0))

        return {
            "anomaly_score": anomaly_score,
            "is_anomaly": max_z > self.threshold,
            "per_feature_zscores": z_scores.tolist(),
        }

    async def save_baseline(self) -> None:
        """Save baseline stats to disk."""
        if self._mean is None:
            return
        self.model_dir.mkdir(parents=True, exist_ok=True)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: np.savez(
                self.baseline_path,
                mean=self._mean,
                std=self._std,
                count=np.array([self._count]),
            ),
        )
        logger.info("zscore_baseline_saved", path=str(self.baseline_path))

    async def load_baseline(self) -> None:
        """Load baseline stats from disk."""
        if not self.baseline_path.exists():
            return
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(None, lambda: np.load(self.baseline_path))
        self._mean = data["mean"]
        self._std = data["std"]
        self._count = int(data["count"][0])
        self.initialized = True
        logger.info("zscore_baseline_loaded", path=str(self.baseline_path))
