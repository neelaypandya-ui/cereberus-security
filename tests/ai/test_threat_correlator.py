"""Tests for the AI Threat Correlator."""

from datetime import datetime, timezone, timedelta

import pytest

from backend.ai.threat_correlator import ThreatCorrelator, SecurityEvent


class TestThreatCorrelator:
    @pytest.fixture
    def correlator(self):
        return ThreatCorrelator(max_events=100, max_age_hours=1.0)

    def test_add_event(self, correlator):
        correlator.add_event_dict("test_event", "test_module")
        assert len(correlator._events) == 1

    def test_event_buffer_limit(self):
        c = ThreatCorrelator(max_events=5)
        for i in range(10):
            c.add_event_dict(f"event_{i}", "test")
        assert len(c._events) == 5

    def test_prune_old_events(self):
        c = ThreatCorrelator(max_events=100, max_age_hours=0.001)  # ~3.6 seconds
        old_event = SecurityEvent(
            event_type="old_event",
            source_module="test",
            severity="low",
            timestamp=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        c.add_event(old_event)
        c._prune_old_events()
        assert len(c._events) == 0

    @pytest.mark.asyncio
    async def test_correlate_no_events(self, correlator):
        result = await correlator.correlate()
        assert result["threat_level"] == "none"
        assert result["correlations"] == []
        assert result["event_count"] == 0

    @pytest.mark.asyncio
    async def test_correlate_single_event(self, correlator):
        correlator.add_event_dict("suspicious_connection", "network_sentinel", severity="high")
        result = await correlator.correlate()
        assert result["event_count"] == 1
        # Single high event -> low threat
        assert result["threat_level"] == "low"

    @pytest.mark.asyncio
    async def test_correlate_pattern_match(self, correlator):
        # Add events that match the "lateral_movement" pattern
        correlator.add_event_dict("suspicious_connection", "network_sentinel", severity="high")
        correlator.add_event_dict("new_process_suspicious", "process_analyzer", severity="high")

        result = await correlator.correlate()
        assert result["threat_level"] in ("high", "critical")
        assert len(result["correlations"]) > 0

        matched = result["correlations"][0]
        assert matched["pattern"] == "lateral_movement"
        assert "suspicious_connection" in matched["matched_event_types"]
        assert "new_process_suspicious" in matched["matched_event_types"]

    @pytest.mark.asyncio
    async def test_correlate_full_compromise(self, correlator):
        # All 3 events for potential_compromise
        correlator.add_event_dict("brute_force_detected", "brute_force_shield", severity="critical")
        correlator.add_event_dict("suspicious_connection", "network_sentinel", severity="high")
        correlator.add_event_dict("file_change", "file_integrity", severity="medium")

        result = await correlator.correlate()
        assert result["threat_level"] == "critical"
        patterns = [c["pattern"] for c in result["correlations"]]
        assert "potential_compromise" in patterns

    @pytest.mark.asyncio
    async def test_correlate_with_dict_events(self, correlator):
        events = [
            {"event_type": "suspicious_connection", "source_module": "net", "severity": "high"},
            {"event_type": "new_process_suspicious", "source_module": "proc", "severity": "high"},
        ]
        result = await correlator.correlate(events)
        assert result["event_count"] == 2

    def test_get_event_buffer(self, correlator):
        for i in range(5):
            correlator.add_event_dict(f"event_{i}", "test")
        buffer = correlator.get_event_buffer(limit=3)
        assert len(buffer) == 3
        # Most recent first
        assert buffer[0]["event_type"] == "event_4"

    @pytest.mark.asyncio
    async def test_multiple_critical_events_raise_threat(self, correlator):
        correlator.add_event_dict("unknown_event_1", "test", severity="critical")
        correlator.add_event_dict("unknown_event_2", "test", severity="critical")
        result = await correlator.correlate()
        # Two critical events -> high threat even without pattern match
        assert result["threat_level"] in ("medium", "high")

    @pytest.mark.asyncio
    async def test_time_window_filtering(self, correlator):
        # Add event that's outside the reconnaissance pattern's 10-min window
        old_event = SecurityEvent(
            event_type="port_scan",
            source_module="test",
            severity="medium",
            timestamp=datetime.now(timezone.utc) - timedelta(minutes=20),
        )
        correlator.add_event(old_event)
        correlator.add_event_dict("suspicious_connection", "test", severity="high")

        result = await correlator.correlate()
        # port_scan is too old for reconnaissance pattern (10 min window)
        # but lateral_movement has 15 min window, and port_scan is 20 min old
        # so only the single high event should contribute
        patterns = [c["pattern"] for c in result["correlations"]]
        assert "reconnaissance" not in patterns
