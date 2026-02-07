"""Tests for the live AI pipeline — AnomalyDetector wired into NetworkSentinel."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.ai.anomaly_detector import AnomalyDetector
from backend.ai.threat_correlator import ThreatCorrelator, ATTACK_PATTERNS
from backend.modules.network_sentinel import NetworkSentinel


@pytest.fixture
def sentinel():
    return NetworkSentinel(config={"poll_interval": 60})


@pytest.fixture
def detector():
    d = AnomalyDetector(model_dir="test_models", threshold=0.5)
    return d


@pytest.fixture
def correlator():
    return ThreatCorrelator(max_events=500, max_age_hours=1.0)


class TestAnomalyDetectorAttachment:
    def test_set_anomaly_detector(self, sentinel, detector):
        assert sentinel._anomaly_detector is None
        sentinel.set_anomaly_detector(detector)
        assert sentinel._anomaly_detector is detector

    def test_get_anomaly_result_default(self, sentinel):
        assert sentinel.get_anomaly_result() is None

    def test_get_anomaly_events_default(self, sentinel):
        assert sentinel.get_anomaly_events() == []


class TestAnomalyDuringScan:
    @pytest.mark.asyncio
    async def test_scan_calls_detector_when_attached(self, sentinel, detector):
        await detector.initialize()
        sentinel.set_anomaly_detector(detector)

        mock_conns = [MagicMock(
            laddr=MagicMock(ip="127.0.0.1", port=8000),
            raddr=MagicMock(ip="10.0.0.1", port=80),
            type=1,
            status="ESTABLISHED",
            pid=1234,
        )]

        with patch("psutil.net_connections", return_value=mock_conns):
            await sentinel._scan_connections()

        result = sentinel.get_anomaly_result()
        assert result is not None
        assert "anomaly_score" in result
        assert "is_anomaly" in result
        assert "threshold" in result

    @pytest.mark.asyncio
    async def test_anomaly_events_tracked_when_anomalous(self, sentinel):
        mock_detector = AsyncMock()
        mock_detector.initialized = True
        mock_detector.extract_features = MagicMock(return_value=[0] * 12)
        mock_detector.predict = AsyncMock(return_value={
            "anomaly_score": 0.9,
            "is_anomaly": True,
            "threshold": 0.5,
        })
        sentinel.set_anomaly_detector(mock_detector)

        with patch("psutil.net_connections", return_value=[]):
            await sentinel._scan_connections()

        events = sentinel.get_anomaly_events()
        assert len(events) == 1
        assert events[0]["anomaly_score"] == 0.9

    @pytest.mark.asyncio
    async def test_no_anomaly_events_when_normal(self, sentinel):
        mock_detector = AsyncMock()
        mock_detector.initialized = True
        mock_detector.extract_features = MagicMock(return_value=[0] * 12)
        mock_detector.predict = AsyncMock(return_value={
            "anomaly_score": 0.1,
            "is_anomaly": False,
            "threshold": 0.5,
        })
        sentinel.set_anomaly_detector(mock_detector)

        with patch("psutil.net_connections", return_value=[]):
            await sentinel._scan_connections()

        events = sentinel.get_anomaly_events()
        assert len(events) == 0


class TestNewCorrelationPatterns:
    def test_anomaly_patterns_exist(self):
        names = [p.name for p in ATTACK_PATTERNS]
        assert "anomaly_with_suspicious_connection" in names
        assert "anomaly_brute_force_compromise" in names

    @pytest.mark.asyncio
    async def test_anomaly_suspicious_connection_correlates(self, correlator):
        await correlator.initialize()
        correlator.add_event_dict("anomaly_detected", "network_sentinel", "high")
        correlator.add_event_dict("suspicious_connection", "network_sentinel", "high")

        result = await correlator.correlate()
        pattern_names = [c["pattern"] for c in result["correlations"]]
        assert "anomaly_with_suspicious_connection" in pattern_names
        assert result["threat_level"] in ("high", "critical")
