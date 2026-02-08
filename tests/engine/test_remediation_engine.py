"""Tests for the RemediationEngine — OS-level security action execution."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
from pathlib import Path

from backend.engine.remediation import RemediationEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(ws_broadcast=None):
    """Create a RemediationEngine with mocked DB session factory and WS broadcast."""
    mock_db_factory = MagicMock()
    mock_ws = ws_broadcast or AsyncMock()
    engine = RemediationEngine(
        db_session_factory=mock_db_factory,
        base_dir=".",
        ws_broadcast_fn=mock_ws,
    )
    # Stub _persist_action so we never hit the real DB; returns a fake action_id
    engine._persist_action = AsyncMock(return_value=1)
    engine._update_action_status = AsyncMock()
    return engine


def _make_subprocess_result(returncode=0, stdout="Ok.", stderr=""):
    """Create a mock subprocess.CompletedProcess."""
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRemediationEngine:

    # 1 — block_ip -----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_block_ip(self):
        """Mock subprocess.run for netsh, verify firewall rule created."""
        engine = _make_engine()
        fake_proc = _make_subprocess_result(returncode=0, stdout="Ok.")

        with patch("backend.engine.remediation.subprocess.run", return_value=fake_proc) as mock_run, \
             patch("backend.engine.remediation.asyncio.get_event_loop") as mock_loop:
            # Make run_in_executor call the lambda directly
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=fake_proc)

            result = await engine.block_ip(
                ip="192.168.1.50",
                duration=7200,
                reason="Suspicious activity",
                incident_id=10,
            )

        assert result["success"] is True
        assert result["action_id"] == 1
        assert result["output"] == "Ok."
        engine._persist_action.assert_awaited_once()
        persist_call_kwargs = engine._persist_action.call_args
        assert persist_call_kwargs[1].get("incident_id") == 10 or persist_call_kwargs[0][0] == "block_ip"
        engine._update_action_status.assert_awaited_once()

    # 2 — unblock_ip ---------------------------------------------------------

    @pytest.mark.asyncio
    async def test_unblock_ip(self):
        """Mock subprocess.run for netsh, verify rule deleted."""
        engine = _make_engine()
        fake_proc = _make_subprocess_result(returncode=0, stdout="Deleted 1 rule(s).")

        with patch("backend.engine.remediation.asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=fake_proc)

            result = await engine.unblock_ip(ip="10.0.0.5", executed_by="admin")

        assert result["success"] is True
        assert result["action_id"] == 1
        assert "Deleted" in result["output"]

    # 3 — kill_process by PID ------------------------------------------------

    @pytest.mark.asyncio
    async def test_kill_process_by_pid(self):
        """Mock psutil.Process, verify terminate called."""
        engine = _make_engine()

        mock_proc = MagicMock()
        mock_proc.name.return_value = "malware.exe"
        mock_proc.terminate = MagicMock()

        with patch("psutil.Process", return_value=mock_proc) as mock_ps:
            result = await engine.kill_process(target="1234", incident_id=5)

        mock_ps.assert_called_once_with(1234)
        mock_proc.terminate.assert_called_once()
        assert result["success"] is True
        assert result["killed"][0]["pid"] == 1234
        assert result["killed"][0]["name"] == "malware.exe"

    # 4 — kill_process by name -----------------------------------------------

    @pytest.mark.asyncio
    async def test_kill_process_by_name(self):
        """Mock subprocess.run for taskkill."""
        engine = _make_engine()
        fake_proc = _make_subprocess_result(returncode=0, stdout="SUCCESS: Terminated.")

        with patch("backend.engine.remediation.asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=fake_proc)

            result = await engine.kill_process(target="malware.exe")

        assert result["success"] is True
        assert result["killed"][0]["name"] == "malware.exe"
        assert "SUCCESS" in result["killed"][0]["output"]

    # 5 — quarantine_file ----------------------------------------------------

    @pytest.mark.asyncio
    async def test_quarantine_file(self, tmp_path):
        """Mock shutil.move, verify file moved to vault and stub created."""
        # Create a real temp file to hash
        test_file = tmp_path / "evil.txt"
        test_file.write_text("malicious content")

        engine = RemediationEngine(
            db_session_factory=None,  # No DB for this test
            base_dir=str(tmp_path),
            ws_broadcast_fn=AsyncMock(),
        )
        engine._persist_action = AsyncMock(return_value=2)
        engine._update_action_status = AsyncMock()

        with patch("backend.engine.remediation.shutil.move") as mock_move:
            result = await engine.quarantine_file(
                path=str(test_file),
                reason="Malware detected",
                executed_by="system",
            )

        assert result["success"] is True
        assert result["action_id"] == 2
        assert result["file_hash"]  # Non-empty SHA-256
        assert len(result["file_hash"]) == 64
        mock_move.assert_called_once()
        # Verify vault path starts in the right place
        move_dest = mock_move.call_args[0][1]
        assert "quarantine_vault" in move_dest

    # 6 — restore_file -------------------------------------------------------

    @pytest.mark.asyncio
    async def test_restore_file(self, tmp_path):
        """Mock DB query for quarantine entry, verify file restored."""
        # Setup mock quarantine entry
        mock_entry = MagicMock()
        mock_entry.vault_path = str(tmp_path / "vault" / "abc123_evil.txt")
        mock_entry.original_path = str(tmp_path / "evil.txt")
        mock_entry.status = "quarantined"

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        # Mock execute to return our entry
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_entry
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        mock_factory = MagicMock(return_value=mock_session)

        engine = RemediationEngine(
            db_session_factory=mock_factory,
            ws_broadcast_fn=AsyncMock(),
        )

        # Mock vault file exists and original path
        with patch("backend.engine.remediation.Path.exists", return_value=True), \
             patch("backend.engine.remediation.os.remove") as mock_rm, \
             patch("backend.engine.remediation.shutil.move") as mock_move:
            result = await engine.restore_file(quarantine_id=1, executed_by="admin")

        assert result["success"] is True
        assert result["restored_path"] == mock_entry.original_path
        mock_move.assert_called_once()
        assert mock_entry.status == "restored"

    # 7 — isolate_network ----------------------------------------------------

    @pytest.mark.asyncio
    async def test_isolate_network(self):
        """Mock subprocess.run for netsh interface disable."""
        engine = _make_engine()
        fake_proc = _make_subprocess_result(returncode=0, stdout="Ok.")

        with patch("backend.engine.remediation.asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=fake_proc)

            result = await engine.isolate_network(
                interface="Ethernet",
                incident_id=3,
                executed_by="operator",
            )

        assert result["success"] is True
        assert result["action_id"] == 1
        engine._persist_action.assert_awaited_once()
        # Verify the persist call included rollback_data with the interface name
        persist_kwargs = engine._persist_action.call_args
        assert "Ethernet" in str(persist_kwargs)

    # 8 — rollback_action ----------------------------------------------------

    @pytest.mark.asyncio
    async def test_rollback_action(self):
        """Mock DB query for action with rollback_data, verify reverse action called."""
        # Setup a completed block_ip action in mock DB
        mock_action = MagicMock()
        mock_action.id = 42
        mock_action.action_type = "block_ip"
        mock_action.target = "10.0.0.1"
        mock_action.status = "completed"
        mock_action.rollback_data_json = json.dumps({"rule_name": "CEREBERUS_REMEDIATION_10_0_0_1"})

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_action
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        mock_factory = MagicMock(return_value=mock_session)

        engine = RemediationEngine(
            db_session_factory=mock_factory,
            ws_broadcast_fn=AsyncMock(),
        )

        # Mock the subprocess call for the netsh delete rule
        fake_proc = _make_subprocess_result(returncode=0, stdout="Deleted 1 rule(s).")

        with patch("backend.engine.remediation.asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=fake_proc)

            result = await engine.rollback_action(action_id=42, executed_by="admin")

        assert result["success"] is True
        # Action status should be updated to rolled_back
        assert mock_action.status == "rolled_back"
        mock_session.commit.assert_awaited()
