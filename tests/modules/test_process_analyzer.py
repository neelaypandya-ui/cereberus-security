"""Tests for the Process Analyzer module."""

from unittest.mock import patch, MagicMock

import pytest

from backend.modules.process_analyzer import ProcessAnalyzer


def _make_mock_proc(pid, name, exe="", cpu=0.0, mem=0.0, status="running", ppid=0):
    """Create a mock process with .info attribute."""
    proc = MagicMock()
    proc.info = {
        "pid": pid,
        "name": name,
        "exe": exe,
        "username": "test_user",
        "cpu_percent": cpu,
        "memory_percent": mem,
        "status": status,
        "create_time": 1700000000.0,
        "ppid": ppid,
    }
    return proc


class TestProcessAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return ProcessAnalyzer(config={
            "poll_interval": 10,
            "suspicious_names": ["mimikatz", "lazagne", "beacon"],
        })

    def test_collect_processes_normal(self, analyzer):
        mock_procs = [
            _make_mock_proc(100, "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe"),
            _make_mock_proc(200, "explorer.exe", r"C:\Windows\explorer.exe"),
        ]
        with patch("backend.modules.process_analyzer.psutil.process_iter", return_value=mock_procs):
            result = analyzer._collect_processes()
        assert len(result) == 2
        assert result[100]["suspicious"] is False
        assert result[200]["suspicious"] is False

    def test_detect_suspicious_name(self, analyzer):
        mock_procs = [
            _make_mock_proc(100, "mimikatz.exe", r"C:\temp\mimikatz.exe"),
        ]
        with patch("backend.modules.process_analyzer.psutil.process_iter", return_value=mock_procs):
            result = analyzer._collect_processes()
        assert result[100]["suspicious"] is True
        assert any("known_malware_name" in r for r in result[100]["suspicious_reasons"])

    def test_detect_high_cpu(self, analyzer):
        mock_procs = [
            _make_mock_proc(100, "crypto_miner.exe", cpu=95.0),
        ]
        with patch("backend.modules.process_analyzer.psutil.process_iter", return_value=mock_procs):
            result = analyzer._collect_processes()
        assert result[100]["suspicious"] is True
        assert any("high_cpu" in r for r in result[100]["suspicious_reasons"])

    def test_detect_high_memory(self, analyzer):
        mock_procs = [
            _make_mock_proc(100, "data_leak.exe", mem=60.0),
        ]
        with patch("backend.modules.process_analyzer.psutil.process_iter", return_value=mock_procs):
            result = analyzer._collect_processes()
        assert result[100]["suspicious"] is True
        assert any("high_memory" in r for r in result[100]["suspicious_reasons"])

    @pytest.mark.asyncio
    async def test_scan_tracks_new_terminated(self, analyzer):
        procs_scan1 = [
            _make_mock_proc(100, "chrome.exe"),
            _make_mock_proc(200, "explorer.exe"),
        ]
        procs_scan2 = [
            _make_mock_proc(200, "explorer.exe"),
            _make_mock_proc(300, "notepad.exe"),
        ]

        with patch("backend.modules.process_analyzer.psutil.process_iter", return_value=procs_scan1):
            await analyzer._scan_processes()

        assert len(analyzer._processes) == 2

        with patch("backend.modules.process_analyzer.psutil.process_iter", return_value=procs_scan2):
            await analyzer._scan_processes()

        # PID 300 is new
        assert any(p["pid"] == 300 for p in analyzer.get_new_processes())
        # PID 100 was terminated
        assert any(p["pid"] == 100 for p in analyzer.get_terminated_processes())

    def test_process_tree(self, analyzer):
        analyzer._processes = {
            1: {"pid": 1, "name": "parent", "ppid": 0, "children": []},
            2: {"pid": 2, "name": "child1", "ppid": 1, "children": []},
            3: {"pid": 3, "name": "child2", "ppid": 1, "children": []},
            4: {"pid": 4, "name": "grandchild", "ppid": 2, "children": []},
        }

        tree = analyzer.get_process_tree(1)
        assert tree is not None
        assert tree["pid"] == 1
        assert len(tree["children"]) == 2

    def test_process_tree_not_found(self, analyzer):
        assert analyzer.get_process_tree(9999) is None

    def test_get_suspicious(self, analyzer):
        analyzer._suspicious = [{"pid": 100, "suspicious": True}]
        assert len(analyzer.get_suspicious()) == 1

    @pytest.mark.asyncio
    async def test_health_check(self, analyzer):
        health = await analyzer.health_check()
        assert "status" in health
        assert "details" in health
