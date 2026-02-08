"""Tests for the PlaybookExecutor — playbook rule evaluation and automated action dispatch."""

import json
import time
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from backend.engine.playbook_executor import PlaybookExecutor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule_obj(
    id=1,
    name="Test Rule",
    trigger_type="alert_severity",
    trigger_conditions=None,
    actions=None,
    cooldown_seconds=300,
    last_triggered=None,
    requires_confirmation=False,
    enabled=True,
    execution_count=0,
):
    """Create a mock PlaybookRule ORM object."""
    rule = MagicMock()
    rule.id = id
    rule.name = name
    rule.trigger_type = trigger_type
    rule.trigger_conditions_json = json.dumps(trigger_conditions or {})
    rule.actions_json = json.dumps(actions or [])
    rule.cooldown_seconds = cooldown_seconds
    rule.last_triggered = last_triggered
    rule.execution_count = execution_count
    rule.requires_confirmation = requires_confirmation
    rule.enabled = enabled
    return rule


def _make_executor(rules=None, remediation_engine=None, ws_broadcast=None):
    """Create a PlaybookExecutor with mocked dependencies."""
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    # Mock DB query returning supplied rules
    mock_result = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = rules or []
    mock_result.scalars.return_value = scalars_mock
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.commit = AsyncMock()

    mock_factory = MagicMock(return_value=mock_session)

    mock_remediation = remediation_engine or AsyncMock()
    mock_ws = ws_broadcast or AsyncMock()

    executor = PlaybookExecutor(
        db_session_factory=mock_factory,
        remediation_engine=mock_remediation,
        ws_broadcast_fn=mock_ws,
    )
    # Force cache to be stale so it refreshes
    executor._cache_timestamp = 0
    # Stub _update_rule_triggered to avoid extra DB round-trips
    executor._update_rule_triggered = AsyncMock()

    return executor


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPlaybookExecutor:

    # 1 — trigger matching alert_severity ------------------------------------

    @pytest.mark.asyncio
    async def test_trigger_matching_alert_severity(self):
        """Rule with trigger_type=alert_severity matches event with matching severity."""
        rule = _make_rule_obj(
            id=1,
            name="Block on Critical Alert",
            trigger_type="alert_severity",
            trigger_conditions={"severity": ["critical", "high"]},
            actions=[{"type": "block_ip", "target": "10.0.0.1"}],
        )
        mock_remediation = AsyncMock()
        mock_remediation.block_ip = AsyncMock(return_value={"action_id": 1, "success": True})

        executor = _make_executor(rules=[rule], remediation_engine=mock_remediation)

        event = {"severity": "critical", "source_module": "brute_force_shield"}
        results = await executor.evaluate_event(event)

        assert len(results) == 1
        assert results[0]["status"] == "executed"
        mock_remediation.block_ip.assert_awaited_once()

    # 2 — trigger matching anomaly_score -------------------------------------

    @pytest.mark.asyncio
    async def test_trigger_matching_anomaly_score(self):
        """Rule with min_score trigger matches event with score above threshold."""
        rule = _make_rule_obj(
            id=2,
            name="Isolate on Anomaly",
            trigger_type="anomaly_score",
            trigger_conditions={"min_score": 0.8},
            actions=[{"type": "isolate_network", "target": "Ethernet"}],
        )
        mock_remediation = AsyncMock()
        mock_remediation.isolate_network = AsyncMock(return_value={"action_id": 2, "success": True})

        executor = _make_executor(rules=[rule], remediation_engine=mock_remediation)

        event = {"anomaly_score": 0.92, "source_module": "network_sentinel"}
        results = await executor.evaluate_event(event)

        assert len(results) == 1
        assert results[0]["status"] == "executed"
        mock_remediation.isolate_network.assert_awaited_once()

    # 3 — cooldown respected -------------------------------------------------

    @pytest.mark.asyncio
    async def test_cooldown_respected(self):
        """Rule that was recently triggered should be skipped during cooldown."""
        recent = datetime.now(timezone.utc) - timedelta(seconds=10)
        rule = _make_rule_obj(
            id=3,
            name="Recently Triggered Rule",
            trigger_type="alert_severity",
            trigger_conditions={"severity": ["critical"]},
            actions=[{"type": "block_ip", "target": "1.2.3.4"}],
            cooldown_seconds=300,
            last_triggered=recent,
        )
        mock_remediation = AsyncMock()
        executor = _make_executor(rules=[rule], remediation_engine=mock_remediation)

        event = {"severity": "critical"}
        results = await executor.evaluate_event(event)

        # Rule should be in cooldown, so no results
        assert len(results) == 0
        mock_remediation.block_ip.assert_not_awaited()

    # 4 — variable substitution ----------------------------------------------

    @pytest.mark.asyncio
    async def test_variable_substitution(self):
        """$details.ip in action target gets replaced with event details."""
        rule = _make_rule_obj(
            id=4,
            name="Dynamic Block",
            trigger_type="alert_severity",
            trigger_conditions={"severity": ["high"]},
            actions=[{"type": "block_ip", "target": "$details.ip", "reason": "auto-block"}],
        )
        mock_remediation = AsyncMock()
        mock_remediation.block_ip = AsyncMock(return_value={"action_id": 4, "success": True})

        executor = _make_executor(rules=[rule], remediation_engine=mock_remediation)

        event = {"severity": "high", "details": {"ip": "203.0.113.42", "port": 4444}}
        results = await executor.evaluate_event(event)

        assert len(results) == 1
        # Verify the resolved IP was passed to block_ip
        call_kwargs = mock_remediation.block_ip.call_args
        assert call_kwargs[1]["ip"] == "203.0.113.42" or call_kwargs.kwargs.get("ip") == "203.0.113.42"

    # 5 — requires_confirmation ----------------------------------------------

    @pytest.mark.asyncio
    async def test_requires_confirmation(self):
        """Rule with requires_confirmation=True broadcasts pending event instead of executing."""
        rule = _make_rule_obj(
            id=5,
            name="Confirm Before Kill",
            trigger_type="alert_severity",
            trigger_conditions={"severity": ["critical"]},
            actions=[{"type": "kill_process", "target": "evil.exe"}],
            requires_confirmation=True,
        )
        mock_remediation = AsyncMock()
        mock_ws = AsyncMock()

        executor = _make_executor(
            rules=[rule],
            remediation_engine=mock_remediation,
            ws_broadcast=mock_ws,
        )

        event = {"severity": "critical"}
        results = await executor.evaluate_event(event)

        assert len(results) == 1
        assert results[0]["status"] == "pending_confirmation"
        assert results[0]["actions"] == []
        # Remediation should NOT have been called
        mock_remediation.kill_process.assert_not_awaited()
        # But WS broadcast should have been called with pending status
        mock_ws.assert_awaited()
        broadcast_data = mock_ws.call_args[0][0]
        assert broadcast_data["type"] == "playbook_trigger"
        assert broadcast_data["data"]["status"] == "pending_confirmation"

    # 6 — disabled rules skipped ---------------------------------------------

    @pytest.mark.asyncio
    async def test_disabled_rules_skipped(self):
        """Disabled rules are not evaluated."""
        rule = _make_rule_obj(
            id=6,
            name="Disabled Rule",
            trigger_type="alert_severity",
            trigger_conditions={"severity": ["critical"]},
            actions=[{"type": "block_ip", "target": "1.2.3.4"}],
            enabled=False,
        )
        mock_remediation = AsyncMock()
        executor = _make_executor(rules=[rule], remediation_engine=mock_remediation)

        # Even though the DB returns it, _refresh_cache only selects enabled=True,
        # but the evaluate_event loop also checks rule["enabled"]. We directly
        # inject the rule into the cache to test the inner guard.
        executor._rules_cache = [PlaybookExecutor._rule_to_dict(rule)]
        executor._cache_timestamp = time.time()  # Fresh cache

        event = {"severity": "critical"}
        results = await executor.evaluate_event(event)

        assert len(results) == 0
        mock_remediation.block_ip.assert_not_awaited()

    # 7 — dry_run mode -------------------------------------------------------

    @pytest.mark.asyncio
    async def test_dry_run(self):
        """dry_run=True returns actions without executing."""
        rule = _make_rule_obj(
            id=7,
            name="Dry Run Rule",
            trigger_type="alert_severity",
            trigger_conditions={"severity": ["high"]},
            actions=[
                {"type": "block_ip", "target": "10.0.0.99"},
                {"type": "kill_process", "target": "miner.exe"},
            ],
        )

        # Build a session that returns the rule for execute_playbook's direct DB query
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = rule
        # Also handle scalars() for _refresh_cache
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [rule]
        mock_result.scalars.return_value = scalars_mock
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        mock_factory = MagicMock(return_value=mock_session)

        mock_remediation = AsyncMock()

        executor = PlaybookExecutor(
            db_session_factory=mock_factory,
            remediation_engine=mock_remediation,
            ws_broadcast_fn=AsyncMock(),
        )

        result = await executor.execute_playbook(
            rule_id=7,
            event_context={"severity": "high"},
            dry_run=True,
        )

        assert result["status"] == "dry_run"
        assert len(result["actions"]) == 2
        assert result["actions"][0]["dry_run"] is True
        assert result["actions"][0]["action_type"] == "block_ip"
        assert result["actions"][1]["action_type"] == "kill_process"
        # Remediation engine should NOT have been called
        mock_remediation.block_ip.assert_not_awaited()
        mock_remediation.kill_process.assert_not_awaited()
