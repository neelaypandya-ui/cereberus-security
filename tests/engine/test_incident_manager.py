"""Tests for the IncidentManager — incident lifecycle management."""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from backend.engine.incident_manager import IncidentManager, VALID_TRANSITIONS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_incident_obj(
    id=1,
    title="Test Incident",
    description="Test description",
    severity="high",
    status="open",
    category=None,
    assigned_to=None,
    source_alert_ids_json=None,
    remediation_actions_json=None,
    timeline_json=None,
    notes=None,
    created_by="system",
    created_at=None,
    updated_at=None,
    resolved_at=None,
):
    """Create a mock Incident ORM object."""
    incident = MagicMock()
    incident.id = id
    incident.title = title
    incident.description = description
    incident.severity = severity
    incident.status = status
    incident.category = category
    incident.assigned_to = assigned_to
    incident.source_alert_ids_json = source_alert_ids_json
    incident.remediation_actions_json = remediation_actions_json
    incident.timeline_json = timeline_json or json.dumps([])
    incident.notes = notes
    incident.created_by = created_by
    incident.created_at = created_at or datetime.now(timezone.utc)
    incident.updated_at = updated_at
    incident.resolved_at = resolved_at
    return incident


def _make_manager(ws_broadcast=None, session_execute_return=None):
    """Create an IncidentManager with a mocked DB session factory."""
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()

    if session_execute_return is not None:
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = session_execute_return
        mock_session.execute = AsyncMock(return_value=mock_result)

    # Track what gets added to the session
    added_objects = []

    def _track_add(obj):
        added_objects.append(obj)

    mock_session.add = MagicMock(side_effect=_track_add)

    mock_factory = MagicMock(return_value=mock_session)
    mock_ws = ws_broadcast or AsyncMock()

    manager = IncidentManager(
        db_session_factory=mock_factory,
        ws_broadcast_fn=mock_ws,
    )

    return manager, mock_session, added_objects


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestIncidentManager:

    # 1 — create_incident ----------------------------------------------------

    @pytest.mark.asyncio
    async def test_create_incident(self):
        """Creates incident with correct fields."""
        mock_ws = AsyncMock()
        manager, mock_session, added_objects = _make_manager(ws_broadcast=mock_ws)

        # When refresh is called, set the id on whatever was added
        async def _fake_refresh(obj):
            obj.id = 100
            obj.title = "Brute Force Detected"
            obj.description = "Multiple login failures"
            obj.severity = "critical"
            obj.status = "open"
            obj.category = "brute_force"
            obj.assigned_to = None
            obj.source_alert_ids_json = json.dumps([1, 2, 3])
            obj.remediation_actions_json = None
            obj.timeline_json = json.dumps([{"event": "created"}])
            obj.notes = None
            obj.created_by = "analyst"
            obj.created_at = datetime.now(timezone.utc)
            obj.updated_at = None
            obj.resolved_at = None

        mock_session.refresh = AsyncMock(side_effect=_fake_refresh)

        result = await manager.create_incident(
            title="Brute Force Detected",
            severity="critical",
            source_alert_ids=[1, 2, 3],
            category="brute_force",
            description="Multiple login failures",
            created_by="analyst",
        )

        assert result["id"] == 100
        assert result["title"] == "Brute Force Detected"
        assert result["severity"] == "critical"
        assert result["status"] == "open"
        mock_session.add.assert_called_once()
        mock_session.commit.assert_awaited_once()
        mock_ws.assert_awaited()

    # 2 — status transitions valid -------------------------------------------

    @pytest.mark.asyncio
    async def test_status_transitions_valid(self):
        """Valid transitions: open -> investigating, investigating -> contained, etc."""
        mock_ws = AsyncMock()

        # Test open -> investigating
        incident = _make_incident_obj(id=1, status="open")
        manager, mock_session, _ = _make_manager(
            ws_broadcast=mock_ws, session_execute_return=incident
        )

        result = await manager.update_status(1, "investigating", actor="analyst")

        assert "error" not in result
        assert incident.status == "investigating"
        mock_session.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_status_transitions_valid_chain(self):
        """Verify multiple valid transitions in sequence."""
        # Verify investigating -> contained
        incident = _make_incident_obj(id=2, status="investigating")
        manager, mock_session, _ = _make_manager(session_execute_return=incident)

        result = await manager.update_status(2, "contained", actor="responder")
        assert "error" not in result
        assert incident.status == "contained"

        # Verify contained -> resolved
        result2 = await manager.update_status(2, "resolved", actor="responder")
        assert "error" not in result2
        assert incident.status == "resolved"
        assert incident.resolved_at is not None

    # 3 — status transitions invalid -----------------------------------------

    @pytest.mark.asyncio
    async def test_status_transitions_invalid(self):
        """open -> resolved should raise error (not a valid transition)."""
        incident = _make_incident_obj(id=3, status="open")
        manager, mock_session, _ = _make_manager(session_execute_return=incident)

        result = await manager.update_status(3, "resolved", actor="analyst")

        assert "error" in result
        assert "Cannot transition" in result["error"]
        assert "open" in result["error"]
        assert "resolved" in result["error"]
        # Status should remain unchanged
        assert incident.status == "open"

    # 4 — auto_create_from_correlation ---------------------------------------

    @pytest.mark.asyncio
    async def test_auto_create_from_correlation(self):
        """Creates incident from correlation data with correct title and category."""
        mock_ws = AsyncMock()

        # We need two session context managers:
        # 1. For dedup check (returns None = no existing)
        # 2. For create_incident (adds the new one)
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.commit = AsyncMock()

        # First call: dedup check returns None; second call: create
        call_count = 0
        async def _fake_execute(stmt):
            nonlocal call_count
            call_count += 1
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = None  # No existing incident
            return mock_result

        mock_session.execute = AsyncMock(side_effect=_fake_execute)

        async def _fake_refresh(obj):
            obj.id = 50
            obj.title = "Auto-detected: Lateral Movement"
            obj.description = "Correlated pattern: lateral_movement"
            obj.severity = "high"
            obj.status = "open"
            obj.category = "correlation_lateral_movement"
            obj.assigned_to = None
            obj.source_alert_ids_json = json.dumps([10, 20])
            obj.remediation_actions_json = None
            obj.timeline_json = json.dumps([{"event": "created"}])
            obj.notes = None
            obj.created_by = "threat_correlator"
            obj.created_at = datetime.now(timezone.utc)
            obj.updated_at = None
            obj.resolved_at = None

        mock_session.refresh = AsyncMock(side_effect=_fake_refresh)
        mock_session.add = MagicMock()

        mock_factory = MagicMock(return_value=mock_session)

        manager = IncidentManager(
            db_session_factory=mock_factory,
            ws_broadcast_fn=mock_ws,
        )

        correlation = {
            "pattern": "lateral_movement",
            "severity": "high",
            "description": "Detected lateral movement indicators",
        }
        events = [
            {"alert_id": 10, "event_type": "suspicious_connection"},
            {"alert_id": 20, "event_type": "brute_force_detected"},
        ]

        result = await manager.auto_create_from_correlation(correlation, events)

        assert result is not None
        assert result["id"] == 50
        assert result["severity"] == "high"
        assert "correlation_lateral_movement" in result["category"]
        assert result["created_by"] == "threat_correlator"

    # 5 — deduplication ------------------------------------------------------

    @pytest.mark.asyncio
    async def test_deduplication(self):
        """Same correlation does not create duplicate incidents."""
        # Return an existing open incident for the dedup check
        existing_incident = _make_incident_obj(
            id=99,
            status="open",
            category="correlation_lateral_movement",
        )

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_incident
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_factory = MagicMock(return_value=mock_session)
        manager = IncidentManager(db_session_factory=mock_factory, ws_broadcast_fn=AsyncMock())

        correlation = {"pattern": "lateral_movement", "severity": "high"}
        events = [{"alert_id": 10}]

        result = await manager.auto_create_from_correlation(correlation, events)

        # Should return None because an existing open incident was found
        assert result is None
        mock_session.add.assert_not_called()

    # 6 — assign_incident ----------------------------------------------------

    @pytest.mark.asyncio
    async def test_assign_incident(self):
        """Assigns incident to user and updates timeline."""
        incident = _make_incident_obj(id=10, status="investigating")
        mock_ws = AsyncMock()
        manager, mock_session, _ = _make_manager(
            ws_broadcast=mock_ws, session_execute_return=incident
        )

        result = await manager.assign_incident(
            incident_id=10, username="responder_1", actor="team_lead"
        )

        assert "error" not in result
        assert incident.assigned_to == "responder_1"
        mock_session.commit.assert_awaited()
        # Timeline should have been updated
        timeline = json.loads(incident.timeline_json)
        assigned_events = [e for e in timeline if e.get("event") == "assigned"]
        assert len(assigned_events) == 1
        assert assigned_events[0]["assigned_to"] == "responder_1"
        mock_ws.assert_awaited()

    # 7 — link_remediation ---------------------------------------------------

    @pytest.mark.asyncio
    async def test_link_remediation(self):
        """Links remediation action to incident."""
        incident = _make_incident_obj(
            id=15,
            status="investigating",
            remediation_actions_json=json.dumps([1, 2]),
        )
        manager, mock_session, _ = _make_manager(session_execute_return=incident)

        result = await manager.link_remediation(incident_id=15, action_id=5)

        assert "error" not in result
        # Verify action_id 5 was appended
        actions = json.loads(incident.remediation_actions_json)
        assert 5 in actions
        # Existing actions preserved
        assert 1 in actions
        assert 2 in actions
        mock_session.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_link_remediation_no_duplicate(self):
        """Linking the same action_id twice should not create duplicates."""
        incident = _make_incident_obj(
            id=16,
            status="open",
            remediation_actions_json=json.dumps([5]),
        )
        manager, mock_session, _ = _make_manager(session_execute_return=incident)

        result = await manager.link_remediation(incident_id=16, action_id=5)

        actions = json.loads(incident.remediation_actions_json)
        assert actions.count(5) == 1
