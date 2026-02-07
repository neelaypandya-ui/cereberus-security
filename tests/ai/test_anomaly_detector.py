"""Tests for the AI Anomaly Detector."""

import tempfile
from pathlib import Path

import numpy as np
import pytest

from backend.ai.anomaly_detector import AnomalyDetector, NetworkAutoencoder


class TestNetworkAutoencoder:
    def test_forward_pass(self):
        model = NetworkAutoencoder(input_dim=12)
        import torch
        x = torch.randn(4, 12)
        output = model(x)
        assert output.shape == (4, 12)

    def test_encoder_decoder_dimensions(self):
        model = NetworkAutoencoder(input_dim=12)
        import torch
        x = torch.randn(1, 12)
        encoded = model.encoder(x)
        assert encoded.shape == (1, 8)
        decoded = model.decoder(encoded)
        assert decoded.shape == (1, 12)


class TestAnomalyDetector:
    @pytest.fixture
    def detector(self):
        return AnomalyDetector(threshold=0.5)

    @pytest.fixture
    def sample_connections(self):
        return [
            {"local_port": 55000, "remote_addr": "10.0.0.1", "remote_port": 443,
             "protocol": "tcp", "status": "ESTABLISHED", "suspicious": False},
            {"local_port": 80, "remote_addr": "", "remote_port": None,
             "protocol": "tcp", "status": "LISTEN", "suspicious": False},
            {"local_port": 60000, "remote_addr": "10.0.0.2", "remote_port": 4444,
             "protocol": "tcp", "status": "ESTABLISHED", "suspicious": True},
            {"local_port": 53, "remote_addr": "", "remote_port": None,
             "protocol": "udp", "status": "NONE", "suspicious": False},
        ]

    def test_extract_features_empty(self, detector):
        features = detector.extract_features([])
        assert features.shape == (12,)
        assert np.all(features == 0)

    def test_extract_features(self, detector, sample_connections):
        features = detector.extract_features(sample_connections)
        assert features.shape == (12,)
        assert features[0] == 4  # total_connections
        assert features[1] == 0.5  # established_ratio (2/4)
        assert features[7] == 0.25  # suspicious_ratio (1/4)

    @pytest.mark.asyncio
    async def test_initialize(self, detector):
        await detector.initialize()
        assert detector.initialized
        assert detector.model is not None

    @pytest.mark.asyncio
    async def test_predict_uninitialized(self, detector):
        result = await detector.predict([0.0] * 12)
        assert "anomaly_score" in result
        assert "is_anomaly" in result
        assert "threshold" in result

    @pytest.mark.asyncio
    async def test_train_and_predict_normal(self, detector, sample_connections):
        await detector.initialize()

        # Create baseline snapshots (all similar)
        snapshots = [sample_connections for _ in range(10)]
        stats = await detector.train(snapshots, epochs=20)

        assert stats["epochs"] == 20
        assert stats["samples"] == 10
        assert stats["final_loss"] >= 0

        # Predict on same data should have low score
        features = detector.extract_features(sample_connections)
        result = await detector.predict(features)
        assert result["anomaly_score"] >= 0

    @pytest.mark.asyncio
    async def test_save_load_model(self, detector, sample_connections):
        with tempfile.TemporaryDirectory() as tmpdir:
            detector.model_dir = Path(tmpdir)
            detector.model_path = Path(tmpdir) / "test_model.pt"
            await detector.initialize()

            snapshots = [sample_connections for _ in range(5)]
            await detector.train(snapshots, epochs=10)
            await detector.save_model()

            assert detector.model_path.exists()

            # Load into new detector
            new_detector = AnomalyDetector()
            new_detector.model_dir = Path(tmpdir)
            new_detector.model_path = Path(tmpdir) / "test_model.pt"
            await new_detector.initialize()

            assert new_detector._feature_mean is not None
            assert new_detector._feature_std is not None
