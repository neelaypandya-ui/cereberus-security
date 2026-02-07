"""Anomaly Detector — PyTorch autoencoder for network anomaly detection.

Uses a small autoencoder model to learn normal network behavior patterns
and detect anomalies via reconstruction error.
"""

import asyncio
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn

from ..utils.logging import get_logger

logger = get_logger("ai.anomaly_detector")


class NetworkAutoencoder(nn.Module):
    """Small autoencoder for network traffic feature vectors."""

    def __init__(self, input_dim: int = 12):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class AnomalyDetector:
    """AI anomaly detection engine using autoencoder reconstruction error."""

    # Feature names for documentation
    FEATURE_NAMES = [
        "total_connections", "established_ratio", "listening_ratio",
        "time_wait_ratio", "close_wait_ratio", "tcp_ratio",
        "udp_ratio", "suspicious_ratio", "unique_remote_ips",
        "unique_local_ports", "unique_remote_ports", "avg_connections_per_ip",
    ]

    def __init__(self, model_dir: Optional[str] = None, threshold: float = 0.5):
        self.model: Optional[NetworkAutoencoder] = None
        self.initialized = False
        self.threshold = threshold
        self.model_dir = Path(model_dir) if model_dir else Path("models")
        self.model_path = self.model_dir / "anomaly_autoencoder.pt"
        self._feature_mean: Optional[np.ndarray] = None
        self._feature_std: Optional[np.ndarray] = None

    async def initialize(self) -> None:
        """Load or create the anomaly detection model."""
        self.model = NetworkAutoencoder(input_dim=len(self.FEATURE_NAMES))
        self.model.eval()
        self.initialized = True

        if self.model_path.exists():
            await self.load_model()

    def extract_features(self, connections: list[dict]) -> np.ndarray:
        """Extract feature vector from connection data.

        Args:
            connections: List of connection dicts with keys like
                local_port, remote_addr, remote_port, protocol, status, suspicious.

        Returns:
            1D numpy array of features.
        """
        if not connections:
            return np.zeros(len(self.FEATURE_NAMES), dtype=np.float32)

        total = len(connections)
        statuses = [c.get("status", "").lower() for c in connections]
        protocols = [c.get("protocol", "").lower() for c in connections]

        established = sum(1 for s in statuses if s == "established")
        listening = sum(1 for s in statuses if s == "listen")
        time_wait = sum(1 for s in statuses if s == "time_wait")
        close_wait = sum(1 for s in statuses if s == "close_wait")
        tcp = sum(1 for p in protocols if p == "tcp")
        udp = sum(1 for p in protocols if p == "udp")
        suspicious = sum(1 for c in connections if c.get("suspicious", False))

        remote_ips = set()
        local_ports = set()
        remote_ports = set()
        for c in connections:
            if c.get("remote_addr"):
                remote_ips.add(c["remote_addr"])
            if c.get("local_port"):
                local_ports.add(c["local_port"])
            if c.get("remote_port"):
                remote_ports.add(c["remote_port"])

        unique_ips = len(remote_ips)
        avg_per_ip = total / max(unique_ips, 1)

        features = np.array([
            total,
            established / max(total, 1),
            listening / max(total, 1),
            time_wait / max(total, 1),
            close_wait / max(total, 1),
            tcp / max(total, 1),
            udp / max(total, 1),
            suspicious / max(total, 1),
            unique_ips,
            len(local_ports),
            len(remote_ports),
            avg_per_ip,
        ], dtype=np.float32)

        return features

    def _normalize(self, features: np.ndarray) -> np.ndarray:
        """Normalize features using stored mean/std."""
        if self._feature_mean is not None and self._feature_std is not None:
            std = np.where(self._feature_std == 0, 1.0, self._feature_std)
            return (features - self._feature_mean) / std
        return features

    async def train(self, connection_snapshots: list[list[dict]], epochs: int = 50, lr: float = 0.001) -> dict:
        """Train the autoencoder on baseline connection data.

        Args:
            connection_snapshots: List of connection lists (each is a snapshot in time).
            epochs: Training epochs.
            lr: Learning rate.

        Returns:
            Training stats dict.
        """
        if not self.initialized:
            await self.initialize()

        features_list = [self.extract_features(snap) for snap in connection_snapshots]
        data = np.stack(features_list)

        # Compute normalization stats
        self._feature_mean = data.mean(axis=0)
        self._feature_std = data.std(axis=0)

        # Normalize
        normalized = np.stack([self._normalize(f) for f in features_list])
        tensor_data = torch.FloatTensor(normalized)

        self.model.train()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        criterion = nn.MSELoss()

        losses = []
        for epoch in range(epochs):
            optimizer.zero_grad()
            output = self.model(tensor_data)
            loss = criterion(output, tensor_data)
            loss.backward()
            optimizer.step()
            losses.append(loss.item())

        self.model.eval()

        return {
            "epochs": epochs,
            "final_loss": losses[-1],
            "samples": len(connection_snapshots),
        }

    async def predict(self, features: np.ndarray | list[float]) -> dict:
        """Run anomaly detection on a feature vector.

        Args:
            features: Feature vector (raw or pre-extracted).

        Returns:
            Dict with anomaly_score, is_anomaly, threshold.
        """
        if not self.initialized:
            await self.initialize()

        if isinstance(features, list):
            features = np.array(features, dtype=np.float32)

        normalized = self._normalize(features)
        tensor_input = torch.FloatTensor(normalized).unsqueeze(0)

        with torch.no_grad():
            output = self.model(tensor_input)
            mse = nn.functional.mse_loss(output, tensor_input).item()

        return {
            "anomaly_score": float(mse),
            "is_anomaly": mse > self.threshold,
            "threshold": self.threshold,
        }

    async def save_model(self) -> None:
        """Save model state to disk."""
        self.model_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "model_state": self.model.state_dict(),
            "feature_mean": self._feature_mean,
            "feature_std": self._feature_std,
            "threshold": self.threshold,
        }
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: torch.save(state, self.model_path))
        logger.info("anomaly_model_saved", path=str(self.model_path))

    async def load_model(self) -> None:
        """Load model state from disk."""
        if not self.model_path.exists():
            logger.warning("anomaly_model_not_found", path=str(self.model_path))
            return

        loop = asyncio.get_event_loop()
        state = await loop.run_in_executor(
            None, lambda: torch.load(self.model_path, weights_only=False)
        )
        self.model.load_state_dict(state["model_state"])
        self._feature_mean = state.get("feature_mean")
        self._feature_std = state.get("feature_std")
        self.threshold = state.get("threshold", self.threshold)
        self.model.eval()
        logger.info("anomaly_model_loaded", path=str(self.model_path))
