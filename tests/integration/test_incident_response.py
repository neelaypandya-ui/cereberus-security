"""Integration test for the full Incident Response pipeline.

Tests the complete chain: correlation event -> IncidentManager auto-creates incident
-> PlaybookExecutor matches rule -> RemediationEngine executes block_ip
-> incident has linked remediation action.

All components are real instances with mocked OS/DB calls — no real system calls.
"""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from backend.engine.remediation import RemediationEngine
from backend.engine.playbook_executor import PlaybookExecutor
from backend.engine.incident_manager import IncidentManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_session_factory():
    """Create a mock DB session factory that tracks all operations.

    Returns (factory, session, tracker) where tracker collects added objects.
    """
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.commit = AsyncMock()

    tracker = {"added": [], "incident": None, "call_index": 0}

    def _track_add(obj):
        tracker["added"].append(obj)

    mock_session.add = MagicMock(side_effect=_track_add)

    mock_factory = MagicMock(return_value=mock_session)
    return mock_factory, mock_session, tracker


def _make_playbook_rule_obj(
    id=1,
    name="Auto-block on correlation",
    trigger_type="correlation_pattern",
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


# ---------------------------------------------------------------------------
# Integration Test
# ---------------------------------------------------------------------------

class TestIncidentResponsePipeline:

    @pytest.mark.asyncio
    async def test_correlation_to_incident_to_playbook_to_remediation(self):
        """Full pipeline integration test:

        1. A threat correlation event is produced
        2. IncidentManager auto-creates an incident from the correlation
        3. PlaybookExecutor evaluates the correlation event and matches a rule
        4. RemediationEngine executes a block_ip action
        5. The incident has the remediation action linked to it
        """
        ws_broadcast = AsyncMock()

        # ---------------------------------------------------------------
        # Step 1: Build the correlation event
        # ---------------------------------------------------------------
        correlation = {
            "pattern": "lateral_movement",
            "severity": "critical",
            "description": "Detected lateral movement from 192.168.1.50",
        }
        contributing_events = [
            {"alert_id": 101, "event_type": "suspicious_connection", "details": {"ip": "192.168.1.50"}},
            {"alert_id": 102, "event_type": "brute_force_detected", "details": {"ip": "192.168.1.50"}},
        ]

        # ---------------------------------------------------------------
        # Step 2: IncidentManager auto-creates an incident
        # ---------------------------------------------------------------
        im_factory, im_session, im_tracker = _make_mock_session_factory()

        # First execute() call = dedup check (no existing)
        # Second execute() call = from create_incident (inside same manager)
        dedup_result = MagicMock()
        dedup_result.scalar_one_or_none.return_value = None  # No existing incident

        im_session.execute = AsyncMock(return_value=dedup_result)

        # When refresh is called after adding the new incident, populate fields
        incident_id = 42

        async def _populate_incident(obj):
            obj.id = incident_id
            obj.title = "Auto-detected: Lateral Movement"
            obj.description = correlation["description"]
            obj.severity = "critical"
            obj.status = "open"
            obj.category = "correlation_lateral_movement"
            obj.assigned_to = None
            obj.source_alert_ids_json = json.dumps([101, 102])
            obj.remediation_actions_json = None
            obj.timeline_json = json.dumps([{"event": "created", "actor": "threat_correlator"}])
            obj.notes = None
            obj.created_by = "threat_correlator"
            obj.created_at = datetime.now(timezone.utc)
            obj.updated_at = None
            obj.resolved_at = None

        im_session.refresh = AsyncMock(side_effect=_populate_incident)

        incident_manager = IncidentManager(
            db_session_factory=im_factory,
            ws_broadcast_fn=ws_broadcast,
        )

        incident = await incident_manager.auto_create_from_correlation(
            correlation, contributing_events
        )

        assert incident is not None
        assert incident["id"] == incident_id
        assert incident["severity"] == "critical"
        assert incident["status"] == "open"

        # ---------------------------------------------------------------
        # Step 3: PlaybookExecutor matches the correlation pattern
        # ---------------------------------------------------------------
        # Create a playbook rule that triggers on lateral_movement correlation
        playbook_rule = _make_playbook_rule_obj(
            id=10,
            name="Block lateral movement source",
            trigger_type="correlation_pattern",
            trigger_conditions={"pattern": "lateral_movement"},
            actions=[
                {"type": "block_ip", "target": "$details.ip", "reason": "Lateral movement detected"},
            ],
        )

        # Build executor with its own session that returns this rule
        pe_factory, pe_session, pe_tracker = _make_mock_session_factory()

        pe_scalars = MagicMock()
        pe_scalars.all.return_value = [playbook_rule]
        pe_result_mock = MagicMock()
        pe_result_mock.scalars.return_value = pe_scalars
        pe_session.execute = AsyncMock(return_value=pe_result_mock)

        # ---------------------------------------------------------------
        # Step 4: RemediationEngine executes block_ip
        # ---------------------------------------------------------------
        remediation_engine = RemediationEngine(
            db_session_factory=None,  # We'll mock _persist_action
            ws_broadcast_fn=ws_broadcast,
        )
        remediation_engine._persist_action = AsyncMock(return_value=77)
        remediation_engine._update_action_status = AsyncMock()

        # Mock the actual subprocess call for netsh
        fake_netsh = MagicMock()
        fake_netsh.returncode = 0
        fake_netsh.stdout = "Ok."
        fake_netsh.stderr = ""

        executor = PlaybookExecutor(
            db_session_factory=pe_factory,
            remediation_engine=remediation_engine,
            ws_broadcast_fn=ws_broadcast,
        )
        executor._cache_timestamp = 0
        executor._update_rule_triggered = AsyncMock()

        # Build the event that the PlaybookExecutor will evaluate
        # This represents the correlation being converted to an evaluable event
        playbook_event = {
            "event_type": "lateral_movement",
            "pattern": "lateral_movement",
            "severity": "critical",
            "details": {"ip": "192.168.1.50"},
            "source_module": "threat_correlator",
        }

        with patch("backend.engine.remediation.asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=fake_netsh)

            playbook_results = await executor.evaluate_event(playbook_event)

        # Verify playbook matched and executed
        assert len(playbook_results) == 1
        assert playbook_results[0]["status"] == "executed"
        assert len(playbook_results[0]["actions"]) == 1

        # Verify block_ip was called with the correct resolved IP
        remediation_engine._persist_action.assert_awaited_once()
        persist_args = remediation_engine._persist_action.call_args
        # First positional arg is action_type, second is target (the IP)
        assert persist_args[0][0] == "block_ip"  # action_type
        assert persist_args[0][1] == "192.168.1.50"  # target

        # ---------------------------------------------------------------
        # Step 5: Link the remediation action to the incident
        # ---------------------------------------------------------------
        # Create a mock incident for the link operation
        link_incident = MagicMock()
        link_incident.id = incident_id
        link_incident.title = "Auto-detected: Lateral Movement"
        link_incident.description = correlation["description"]
        link_incident.severity = "critical"
        link_incident.status = "open"
        link_incident.category = "correlation_lateral_movement"
        link_incident.assigned_to = None
        link_incident.source_alert_ids_json = json.dumps([101, 102])
        link_incident.remediation_actions_json = None  # No actions yet
        link_incident.timeline_json = json.dumps([{"event": "created"}])
        link_incident.notes = None
        link_incident.created_by = "threat_correlator"
        link_incident.created_at = datetime.now(timezone.utc)
        link_incident.updated_at = None
        link_incident.resolved_at = None

        link_result = MagicMock()
        link_result.scalar_one_or_none.return_value = link_incident
        im_session.execute = AsyncMock(return_value=link_result)

        action_id = 77  # The action_id returned by _persist_action
        link_response = await incident_manager.link_remediation(
            incident_id=incident_id,
            action_id=action_id,
        )

        assert "error" not in link_response
        # Verify the remediation action ID is now linked
        linked_actions = json.loads(link_incident.remediation_actions_json)
        assert action_id in linked_actions

        # ---------------------------------------------------------------
        # Verify full pipeline integrity
        # ---------------------------------------------------------------
        # WS broadcast was called multiple times (incident created, playbook triggered, block_ip)
        assert ws_broadcast.await_count >= 2

        # The remediation action was persisted
        remediation_engine._persist_action.assert_awaited_once()
        remediation_engine._update_action_status.assert_awaited_once()

        # The playbook rule was marked as triggered
        executor._update_rule_triggered.assert_awaited_once_with(10)
