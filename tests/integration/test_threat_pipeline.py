"""Integration tests for the full threat pipeline.

Tests that all modules feed events through ThreatIntelligence to ThreatCorrelator,
and that new event types and attack patterns work correctly end-to-end.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.ai.threat_correlator import ThreatCorrelator, ATTACK_PATTERNS
from backend.modules.threat_intelligence import ThreatIntelligence


@pytest.fixture
def correlator():
    return ThreatCorrelator(max_events=1000, max_age_hours=1.0)


@pytest.fixture
def threat_intel():
    return ThreatIntelligence(config={"poll_interval": 60, "feed_max_events": 500})


class TestNewAttackPatterns:
    def test_all_expected_patterns_exist(self):
        names = [p.name for p in ATTACK_PATTERNS]
        expected = [
            "potential_compromise",
            "lateral_movement",
            "phishing_attack",
            "data_exfiltration",
            "reconnaissance",
            "anomaly_with_suspicious_connection",
            "anomaly_brute_force_compromise",
            "persistence_after_compromise",
            "resource_abuse_attack",
            "vulnerability_exploitation",
        ]
        for name in expected:
            assert name in names, f"Missing pattern: {name}"

    def test_total_pattern_count(self):
        assert len(ATTACK_PATTERNS) == 10


class TestNewEventTypes:
    @pytest.mark.asyncio
    async def test_persistence_change_event(self, correlator):
        await correlator.initialize()
        correlator.add_event_dict("persistence_change", "persistence_scanner", "high")
        correlator.add_event_dict("brute_force_detected", "brute_force_shield", "high")
        correlator.add_event_dict("suspicious_connection", "network_sentinel", "high")

        result = await correlator.correlate()
        patterns = [c["pattern"] for c in result["correlations"]]
        assert "persistence_after_compromise" in patterns

    @pytest.mark.asyncio
    async def test_resource_spike_event(self, correlator):
        await correlator.initialize()
        correlator.add_event_dict("resource_spike", "resource_monitor", "medium")
        correlator.add_event_dict("suspicious_connection", "network_sentinel", "high")

        result = await correlator.correlate()
        patterns = [c["pattern"] for c in result["correlations"]]
        assert "resource_abuse_attack" in patterns

    @pytest.mark.asyncio
    async def test_vulnerability_exploitation_event(self, correlator):
        await correlator.initialize()
        correlator.add_event_dict("vulnerability_found", "vuln_scanner", "critical")
        correlator.add_event_dict("suspicious_connection", "network_sentinel", "high")

        result = await correlator.correlate()
        patterns = [c["pattern"] for c in result["correlations"]]
        assert "vulnerability_exploitation" in patterns

    @pytest.mark.asyncio
    async def test_anomaly_detected_event(self, correlator):
        await correlator.initialize()
        correlator.add_event_dict("anomaly_detected", "network_sentinel", "high")
        correlator.add_event_dict("suspicious_connection", "network_sentinel", "high")

        result = await correlator.correlate()
        patterns = [c["pattern"] for c in result["correlations"]]
        assert "anomaly_with_suspicious_connection" in patterns


class TestThreatIntelligenceModuleCollection:
    @pytest.mark.asyncio
    async def test_collects_from_vuln_scanner(self, threat_intel):
        mock_vs = MagicMock()
        mock_vs.get_vulnerabilities.return_value = [
            {"title": "Open FTP", "severity": "critical", "category": "open_port"},
        ]
        threat_intel.set_module_refs({"vuln_scanner": mock_vs})

        threat_intel._ensure_correlator()
        await threat_intel._collect_and_correlate()

        feed = threat_intel.get_threat_feed()
        event_types = [e["event_type"] for e in feed]
        assert "vulnerability_found" in event_types

    @pytest.mark.asyncio
    async def test_collects_from_persistence_scanner(self, threat_intel):
        mock_ps = MagicMock()
        mock_ps.get_changes.return_value = [
            {"source": "registry", "name": "malware", "status": "added"},
        ]
        threat_intel.set_module_refs({"persistence_scanner": mock_ps})

        threat_intel._ensure_correlator()
        await threat_intel._collect_and_correlate()

        feed = threat_intel.get_threat_feed()
        event_types = [e["event_type"] for e in feed]
        assert "persistence_change" in event_types

    @pytest.mark.asyncio
    async def test_collects_from_resource_monitor(self, threat_intel):
        mock_rm = MagicMock()
        mock_rm.get_alerts.return_value = [
            {"timestamp": "2024-01-01T00:00:00", "breaches": ["CPU at 95%"]},
        ]
        threat_intel.set_module_refs({"resource_monitor": mock_rm})

        threat_intel._ensure_correlator()
        await threat_intel._collect_and_correlate()

        feed = threat_intel.get_threat_feed()
        event_types = [e["event_type"] for e in feed]
        assert "resource_spike" in event_types

    @pytest.mark.asyncio
    async def test_collects_anomaly_from_network_sentinel(self, threat_intel):
        mock_ns = MagicMock()
        mock_ns.get_flagged_connections.return_value = []
        mock_ns.get_anomaly_result.return_value = {
            "anomaly_score": 0.9,
            "is_anomaly": True,
            "threshold": 0.5,
        }
        threat_intel.set_module_refs({"network_sentinel": mock_ns})

        threat_intel._ensure_correlator()
        await threat_intel._collect_and_correlate()

        feed = threat_intel.get_threat_feed()
        event_types = [e["event_type"] for e in feed]
        assert "anomaly_detected" in event_types
