"""Tests for the Persistence Scanner module."""

import asyncio
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from backend.modules.persistence_scanner import PersistenceScanner


@pytest.fixture
def scanner():
    return PersistenceScanner(config={"scan_interval": 600})


def make_entries(names):
    return [
        {"source": "registry", "source_label": "HKLM_Run", "path": "HKLM\\...\\Run", "name": n, "value": f"C:\\{n}.exe"}
        for n in names
    ]


class TestPersistenceScannerBasic:
    def test_init_defaults(self, scanner):
        assert scanner._scan_interval == 600
        assert scanner._baseline_established is False
        assert scanner._entries == []

    def test_get_entries_empty(self, scanner):
        assert scanner.get_entries() == []

    def test_get_changes_empty(self, scanner):
        assert scanner.get_changes() == []

    def test_get_last_scan_none(self, scanner):
        assert scanner.get_last_scan() is None


class TestBaselineAndChanges:
    @pytest.mark.asyncio
    async def test_first_scan_establishes_baseline(self, scanner):
        entries = make_entries(["app1", "app2"])
        with patch.object(scanner, "_collect_all_entries", return_value=entries):
            await scanner.run_scan()

        assert scanner._baseline_established is True
        assert len(scanner.get_entries()) == 2
        assert len(scanner.get_changes()) == 0

    @pytest.mark.asyncio
    async def test_detect_added_entry(self, scanner):
        entries1 = make_entries(["app1"])
        entries2 = make_entries(["app1", "malware"])

        with patch.object(scanner, "_collect_all_entries", return_value=entries1):
            await scanner.run_scan()

        with patch.object(scanner, "_collect_all_entries", return_value=entries2):
            await scanner.run_scan()

        changes = scanner.get_changes()
        assert len(changes) == 1
        assert changes[0]["name"] == "malware"
        assert changes[0]["status"] == "added"

    @pytest.mark.asyncio
    async def test_detect_removed_entry(self, scanner):
        entries1 = make_entries(["app1", "app2"])
        entries2 = make_entries(["app1"])

        with patch.object(scanner, "_collect_all_entries", return_value=entries1):
            await scanner.run_scan()

        with patch.object(scanner, "_collect_all_entries", return_value=entries2):
            await scanner.run_scan()

        changes = scanner.get_changes()
        assert len(changes) == 1
        assert changes[0]["name"] == "app2"
        assert changes[0]["status"] == "removed"

    @pytest.mark.asyncio
    async def test_detect_changed_entry(self, scanner):
        entries1 = make_entries(["app1"])
        entries2 = [{"source": "registry", "source_label": "HKLM_Run", "path": "HKLM\\...\\Run", "name": "app1", "value": "C:\\new_path.exe"}]

        with patch.object(scanner, "_collect_all_entries", return_value=entries1):
            await scanner.run_scan()

        with patch.object(scanner, "_collect_all_entries", return_value=entries2):
            await scanner.run_scan()

        changes = scanner.get_changes()
        assert len(changes) == 1
        assert changes[0]["status"] == "changed"

    @pytest.mark.asyncio
    async def test_no_changes_when_same(self, scanner):
        entries = make_entries(["app1", "app2"])

        with patch.object(scanner, "_collect_all_entries", return_value=entries):
            await scanner.run_scan()
            await scanner.run_scan()

        assert len(scanner.get_changes()) == 0


class TestComputeChanges:
    def test_static_compute_changes(self):
        baseline = make_entries(["a", "b"])
        current = make_entries(["b", "c"])

        changes = PersistenceScanner._compute_changes(baseline, current)
        statuses = {c["name"]: c["status"] for c in changes}
        assert statuses["a"] == "removed"
        assert statuses["c"] == "added"
        assert "b" not in statuses


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_health_check(self, scanner):
        health = await scanner.health_check()
        assert health["status"] == "initialized"
        assert "details" in health
        assert health["details"]["entry_count"] == 0


class TestGetLastScan:
    @pytest.mark.asyncio
    async def test_last_scan_after_scan(self, scanner):
        with patch.object(scanner, "_collect_all_entries", return_value=[]):
            await scanner.run_scan()

        last = scanner.get_last_scan()
        assert last is not None
        assert "timestamp" in last
        assert last["baseline_established"] is True
