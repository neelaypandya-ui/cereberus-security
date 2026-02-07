"""Threat Forecaster — LSTM-based resource prediction and threat forecasting.

Uses a small LSTM to predict future resource usage (CPU, memory, disk, net I/O)
and generate proactive threat alerts when predicted values breach thresholds.
"""

import asyncio
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn

from ..utils.logging import get_logger

logger = get_logger("ai.threat_forecaster")


class ResourceLSTM(nn.Module):
    """Small LSTM for resource time-series prediction."""

    def __init__(self, input_size: int = 5, hidden_size: int = 32, num_layers: int = 1):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
        )
        self.fc = nn.Linear(hidden_size, input_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: (batch, seq_len, input_size)
        lstm_out, _ = self.lstm(x)
        # Take last timestep output
        last_output = lstm_out[:, -1, :]
        prediction = self.fc(last_output)
        return prediction


# Feature names for the 5 resource metrics
FEATURE_NAMES = ["cpu_percent", "memory_percent", "disk_percent", "net_bytes_sent", "net_bytes_recv"]
SEQUENCE_LENGTH = 30  # 30 snapshots = 5 min lookback at 10s intervals


class ThreatForecaster:
    """Predicts future resource usage and generates forecast alerts."""

    def __init__(self, model_dir: Optional[str] = None):
        self.model_dir = Path(model_dir) if model_dir else Path("models")
        self.model_path = self.model_dir / "threat_forecaster.pt"
        self.model: Optional[ResourceLSTM] = None
        self.initialized = False
        self._feature_mean: Optional[np.ndarray] = None
        self._feature_std: Optional[np.ndarray] = None
        self._last_prediction: Optional[dict] = None

    async def initialize(self) -> None:
        """Initialize the LSTM model."""
        self.model = ResourceLSTM(input_size=len(FEATURE_NAMES))
        self.model.eval()
        self.initialized = True

        if self.model_path.exists():
            await self.load_model()

    def _snapshots_to_matrix(self, snapshots: list[dict]) -> np.ndarray:
        """Convert resource snapshots to a feature matrix."""
        rows = []
        for snap in snapshots:
            row = [
                snap.get("cpu_percent", 0.0),
                snap.get("memory_percent", 0.0),
                snap.get("disk_percent", 0.0),
                snap.get("net_bytes_sent", 0.0),
                snap.get("net_bytes_recv", 0.0),
            ]
            rows.append(row)
        return np.array(rows, dtype=np.float32)

    def _normalize(self, data: np.ndarray) -> np.ndarray:
        """Normalize using stored mean/std."""
        if self._feature_mean is not None and self._feature_std is not None:
            std = np.where(self._feature_std == 0, 1.0, self._feature_std)
            return (data - self._feature_mean) / std
        return data

    def _denormalize(self, data: np.ndarray) -> np.ndarray:
        """Reverse normalization."""
        if self._feature_mean is not None and self._feature_std is not None:
            return data * self._feature_std + self._feature_mean
        return data

    async def train(self, snapshots: list[dict], epochs: int = 50, lr: float = 0.001) -> dict:
        """Train the LSTM on historical resource snapshots.

        Creates sequences of SEQUENCE_LENGTH and trains to predict the next timestep.

        Args:
            snapshots: List of resource snapshot dicts.
            epochs: Training epochs.
            lr: Learning rate.

        Returns:
            Training stats dict.
        """
        if not self.initialized:
            await self.initialize()

        matrix = self._snapshots_to_matrix(snapshots)
        if len(matrix) < SEQUENCE_LENGTH + 1:
            return {"error": f"Need at least {SEQUENCE_LENGTH + 1} snapshots, got {len(matrix)}"}

        # Compute normalization stats
        self._feature_mean = matrix.mean(axis=0)
        self._feature_std = matrix.std(axis=0)
        self._feature_std[self._feature_std == 0] = 1.0

        normalized = self._normalize(matrix)

        # Create sequences
        X_sequences = []
        y_targets = []
        for i in range(len(normalized) - SEQUENCE_LENGTH):
            X_sequences.append(normalized[i : i + SEQUENCE_LENGTH])
            y_targets.append(normalized[i + SEQUENCE_LENGTH])

        X = torch.FloatTensor(np.array(X_sequences))
        y = torch.FloatTensor(np.array(y_targets))

        self.model.train()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        criterion = nn.MSELoss()

        losses = []
        for epoch in range(epochs):
            optimizer.zero_grad()
            output = self.model(X)
            loss = criterion(output, y)
            loss.backward()
            optimizer.step()
            losses.append(loss.item())

        self.model.eval()

        return {
            "epochs": epochs,
            "final_loss": losses[-1],
            "samples": len(X_sequences),
            "sequence_length": SEQUENCE_LENGTH,
        }

    async def predict_next(self, recent_snapshots: list[dict]) -> dict:
        """Predict the next timestep from the most recent snapshots.

        Args:
            recent_snapshots: Last SEQUENCE_LENGTH snapshots.

        Returns:
            Dict with predicted values for each feature.
        """
        if not self.initialized or self.model is None:
            return {}

        matrix = self._snapshots_to_matrix(recent_snapshots[-SEQUENCE_LENGTH:])
        if len(matrix) < SEQUENCE_LENGTH:
            return {}

        normalized = self._normalize(matrix)
        tensor_input = torch.FloatTensor(normalized).unsqueeze(0)

        with torch.no_grad():
            output = self.model(tensor_input)
            predicted_normalized = output.squeeze(0).numpy()

        predicted = self._denormalize(predicted_normalized)

        result = {}
        for i, name in enumerate(FEATURE_NAMES):
            result[name] = float(np.clip(predicted[i], 0.0, 100.0 if "percent" in name else float("inf")))

        self._last_prediction = result
        return result

    async def predict_trend(self, recent_snapshots: list[dict], steps: int = 6) -> list[dict]:
        """Predict multiple future timesteps by feeding predictions back in.

        Args:
            recent_snapshots: Recent snapshots for initial context.
            steps: Number of future predictions (each ~10 min apart).

        Returns:
            List of predicted value dicts.
        """
        if not self.initialized or self.model is None:
            return []

        matrix = self._snapshots_to_matrix(recent_snapshots[-SEQUENCE_LENGTH:])
        if len(matrix) < SEQUENCE_LENGTH:
            return []

        predictions = []
        current_sequence = self._normalize(matrix.copy())

        for step in range(steps):
            tensor_input = torch.FloatTensor(current_sequence[-SEQUENCE_LENGTH:]).unsqueeze(0)

            with torch.no_grad():
                output = self.model(tensor_input)
                pred_normalized = output.squeeze(0).numpy()

            pred_raw = self._denormalize(pred_normalized)

            prediction = {}
            for i, name in enumerate(FEATURE_NAMES):
                prediction[name] = float(np.clip(pred_raw[i], 0.0, 100.0 if "percent" in name else float("inf")))
            prediction["step"] = step + 1
            prediction["minutes_ahead"] = (step + 1) * 10
            predictions.append(prediction)

            # Append prediction to sequence for next step
            current_sequence = np.vstack([current_sequence, pred_normalized.reshape(1, -1)])

        return predictions

    def check_forecast_alerts(
        self,
        predictions: list[dict],
        thresholds: dict | None = None,
    ) -> list[dict]:
        """Check predictions against thresholds and generate forecast alerts.

        Args:
            predictions: List from predict_trend().
            thresholds: Dict of metric_name -> threshold. Defaults to standard thresholds.

        Returns:
            List of forecast alert dicts.
        """
        if thresholds is None:
            thresholds = {
                "cpu_percent": 90.0,
                "memory_percent": 85.0,
                "disk_percent": 90.0,
            }

        alerts = []
        for pred in predictions:
            for metric, threshold in thresholds.items():
                value = pred.get(metric, 0.0)
                if value >= threshold:
                    alerts.append({
                        "metric": metric,
                        "predicted_value": round(value, 1),
                        "threshold": threshold,
                        "minutes_until_breach": pred.get("minutes_ahead", 0),
                        "step": pred.get("step", 0),
                    })
        return alerts

    def get_last_prediction(self) -> Optional[dict]:
        return self._last_prediction

    async def save_model(self) -> None:
        """Save LSTM model to disk."""
        if self.model is None:
            return
        self.model_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "model_state": self.model.state_dict(),
            "feature_mean": self._feature_mean,
            "feature_std": self._feature_std,
        }
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: torch.save(state, self.model_path))
        logger.info("threat_forecaster_saved", path=str(self.model_path))

    async def load_model(self) -> None:
        """Load LSTM model from disk."""
        if not self.model_path.exists():
            return
        loop = asyncio.get_event_loop()
        state = await loop.run_in_executor(
            None, lambda: torch.load(self.model_path, weights_only=False)
        )
        if self.model is None:
            self.model = ResourceLSTM(input_size=len(FEATURE_NAMES))
        self.model.load_state_dict(state["model_state"])
        self._feature_mean = state.get("feature_mean")
        self._feature_std = state.get("feature_std")
        self.model.eval()
        self.initialized = True
        logger.info("threat_forecaster_loaded", path=str(self.model_path))
