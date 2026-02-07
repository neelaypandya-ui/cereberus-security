"""Tests for the Threat Intelligence module."""

from unittest.mock import MagicMock

import pytest

from backend.modules.threat_intelligence import ThreatIntelligence


class TestThreatIntelligence:
    @pytest.fixture
    def ti(self):
        return ThreatIntelligence(config={
            "feed_max_events": 100,
            "correlation_window": 1.0,
        })

    def test_initial_state(self, ti):
        assert ti.get_threat_level() == "none"
        assert ti.get_threat_feed() == []
        assert ti.get_correlations() == []

    def test_set_module_refs(self, ti):
        mock_ns = MagicMock()
        mock_bfs = MagicMock()
        ti.set_module_refs({
            "network_sentinel": mock_ns,
            "brute_force_shield": mock_bfs,
        })
        assert "network_sentinel" in ti._module_refs
        assert "brute_force_shield" in ti._module_refs

    @pytest.mark.asyncio
    async def test_collect_from_network_sentinel(self, ti):
        mock_ns = MagicMock()
        mock_ns.get_flagged_connections.return_value = [
            {"remote_addr": "10.0.0.1", "remote_port": 4444, "suspicious": True},
        ]
        # Prevent anomaly collection from also adding an event
        mock_ns.get_anomaly_result.return_value = None
        ti.set_module_refs({"network_sentinel": mock_ns})
        ti._ensure_correlator()

        await ti._collect_and_correlate()

        feed = ti.get_threat_feed()
        assert len(feed) == 1
        assert feed[0]["event_type"] == "suspicious_connection"

    @pytest.mark.asyncio
    async def test_collect_from_process_analyzer(self, ti):
        mock_pa = MagicMock()
        mock_pa.get_suspicious.return_value = [
            {"pid": 100, "name": "mimikatz.exe", "suspicious": True},
        ]
        ti.set_module_refs({"process_analyzer": mock_pa})
        ti._ensure_correlator()

        await ti._collect_and_correlate()

        feed = ti.get_threat_feed()
        assert len(feed) == 1
        assert feed[0]["event_type"] == "new_process_suspicious"

    @pytest.mark.asyncio
    async def test_threat_level_updates(self, ti):
        mock_ns = MagicMock()
        mock_ns.get_flagged_connections.return_value = [
            {"remote_addr": "10.0.0.1", "remote_port": 4444},
        ]
        mock_pa = MagicMock()
        mock_pa.get_suspicious.return_value = [
            {"pid": 100, "name": "beacon.exe"},
        ]
        ti.set_module_refs({
            "network_sentinel": mock_ns,
            "process_analyzer": mock_pa,
        })
        ti._ensure_correlator()

        await ti._collect_and_correlate()

        # Should detect lateral_movement pattern
        level = ti.get_threat_level()
        assert level in ("low", "medium", "high", "critical")

    @pytest.mark.asyncio
    async def test_feed_limit(self, ti):
        mock_ns = MagicMock()
        mock_ns.get_flagged_connections.return_value = [
            {"remote_addr": f"10.0.0.{i}", "remote_port": 4444}
            for i in range(150)
        ]
        ti._feed_max = 50
        ti.set_module_refs({"network_sentinel": mock_ns})
        ti._ensure_correlator()

        await ti._collect_and_correlate()

        assert len(ti.get_threat_feed()) <= 50

    @pytest.mark.asyncio
    async def test_empty_modules(self, ti):
        ti.set_module_refs({})
        ti._ensure_correlator()

        await ti._collect_and_correlate()
        assert ti.get_threat_level() == "none"

    @pytest.mark.asyncio
    async def test_module_exception_handling(self, ti):
        mock_ns = MagicMock()
        mock_ns.get_flagged_connections.side_effect = RuntimeError("test error")
        ti.set_module_refs({"network_sentinel": mock_ns})
        ti._ensure_correlator()

        # Should not crash
        await ti._collect_and_correlate()

    @pytest.mark.asyncio
    async def test_start_stop(self, ti):
        await ti.start()
        assert ti.running is True
        assert ti.health_status == "running"

        await ti.stop()
        assert ti.running is False
        assert ti.health_status == "stopped"

    @pytest.mark.asyncio
    async def test_health_check(self, ti):
        health = await ti.health_check()
        assert "status" in health
        assert "details" in health
        assert "threat_level" in health["details"]

    @pytest.mark.asyncio
    async def test_correlations_exposed(self, ti):
        mock_ns = MagicMock()
        mock_ns.get_flagged_connections.return_value = [
            {"remote_addr": "10.0.0.1", "remote_port": 4444},
        ]
        mock_pa = MagicMock()
        mock_pa.get_suspicious.return_value = [
            {"pid": 100, "name": "beacon.exe"},
        ]
        ti.set_module_refs({
            "network_sentinel": mock_ns,
            "process_analyzer": mock_pa,
        })
        ti._ensure_correlator()

        await ti._collect_and_correlate()

        corrs = ti.get_correlations()
        assert isinstance(corrs, list)
