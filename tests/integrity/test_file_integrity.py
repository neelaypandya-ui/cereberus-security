"""Tests for File Integrity module."""

import hashlib
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.modules.file_integrity import FileIntegrity


class TestFileIntegrity:
    def setup_method(self):
        self.fi = FileIntegrity(config={
            "scan_interval": 300,
            "watched_paths": [],
            "exclusion_patterns": ["*.tmp", "*.log", "*.pyc", "__pycache__"],
            "max_file_size": 50_000_000,
        })

    def test_initial_state(self):
        """Should start with empty baselines."""
        assert self.fi._baselines == {}
        assert self.fi._baseline_established is False
        assert self.fi._last_scan is None
        assert not self.fi.running

    def test_is_excluded_match(self):
        """Should exclude files matching patterns."""
        assert self.fi._is_excluded("file.tmp") is True
        assert self.fi._is_excluded("app.log") is True
        assert self.fi._is_excluded("module.pyc") is True
        assert self.fi._is_excluded("__pycache__") is True

    def test_is_excluded_no_match(self):
        """Should not exclude normal files."""
        assert self.fi._is_excluded("main.py") is False
        assert self.fi._is_excluded("config.json") is False
        assert self.fi._is_excluded("README.md") is False

    def test_hash_file(self):
        """Should compute correct SHA-256 hash."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"hello world")
            fpath = Path(f.name)

        try:
            result = self.fi._hash_file(fpath)
            expected = hashlib.sha256(b"hello world").hexdigest()
            assert result == expected
        finally:
            os.unlink(fpath)

    def test_hash_file_large(self):
        """Should skip files exceeding max_file_size."""
        fi = FileIntegrity(config={"max_file_size": 10})
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"x" * 100)
            fpath = Path(f.name)

        try:
            result = fi._hash_file(fpath)
            assert result is None
        finally:
            os.unlink(fpath)

    def test_hash_file_nonexistent(self):
        """Should return None for nonexistent files."""
        result = self.fi._hash_file(Path("/nonexistent/file.txt"))
        assert result is None

    def test_compare_hashes_no_changes(self):
        """Should detect no changes when hashes match."""
        baseline = {"a.py": "abc123", "b.py": "def456"}
        current = {"a.py": "abc123", "b.py": "def456"}
        changes = FileIntegrity._compare_hashes(baseline, current)
        assert changes["modified"] == []
        assert changes["added"] == []
        assert changes["deleted"] == []

    def test_compare_hashes_modified(self):
        """Should detect modified files."""
        baseline = {"a.py": "abc123", "b.py": "def456"}
        current = {"a.py": "changed!", "b.py": "def456"}
        changes = FileIntegrity._compare_hashes(baseline, current)
        assert changes["modified"] == ["a.py"]
        assert changes["added"] == []
        assert changes["deleted"] == []

    def test_compare_hashes_added(self):
        """Should detect added files."""
        baseline = {"a.py": "abc123"}
        current = {"a.py": "abc123", "new.py": "newfile"}
        changes = FileIntegrity._compare_hashes(baseline, current)
        assert changes["modified"] == []
        assert changes["added"] == ["new.py"]
        assert changes["deleted"] == []

    def test_compare_hashes_deleted(self):
        """Should detect deleted files."""
        baseline = {"a.py": "abc123", "old.py": "willdelete"}
        current = {"a.py": "abc123"}
        changes = FileIntegrity._compare_hashes(baseline, current)
        assert changes["modified"] == []
        assert changes["added"] == []
        assert changes["deleted"] == ["old.py"]

    def test_compare_hashes_all_types(self):
        """Should detect all types of changes simultaneously."""
        baseline = {"kept.py": "same", "modified.py": "old", "deleted.py": "gone"}
        current = {"kept.py": "same", "modified.py": "new", "added.py": "fresh"}
        changes = FileIntegrity._compare_hashes(baseline, current)
        assert changes["modified"] == ["modified.py"]
        assert changes["added"] == ["added.py"]
        assert changes["deleted"] == ["deleted.py"]

    @pytest.mark.asyncio
    async def test_first_scan_establishes_baseline(self):
        """First scan should establish baseline, not report changes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            (Path(tmpdir) / "file1.txt").write_text("hello")
            (Path(tmpdir) / "file2.txt").write_text("world")

            fi = FileIntegrity(config={
                "watched_paths": [tmpdir],
                "exclusion_patterns": [],
                "max_file_size": 50_000_000,
            })

            result = await fi.run_scan()

            assert result["type"] == "baseline"
            assert result["files_scanned"] == 2
            assert result["changes"]["modified"] == []
            assert result["changes"]["added"] == []
            assert result["changes"]["deleted"] == []
            assert fi._baseline_established is True

    @pytest.mark.asyncio
    async def test_second_scan_detects_changes(self):
        """Second scan should detect modifications."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "file1.txt"
            fpath.write_text("original")

            fi = FileIntegrity(config={
                "watched_paths": [tmpdir],
                "exclusion_patterns": [],
                "max_file_size": 50_000_000,
            })

            # First scan (baseline)
            await fi.run_scan()

            # Modify the file
            fpath.write_text("modified content")

            # Second scan (should detect changes)
            result = await fi.run_scan()

            assert result["type"] == "scan"
            assert len(result["changes"]["modified"]) == 1
            assert str(fpath) in result["changes"]["modified"]

    @pytest.mark.asyncio
    async def test_scan_detects_added_files(self):
        """Scan should detect newly added files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "existing.txt").write_text("existing")

            fi = FileIntegrity(config={
                "watched_paths": [tmpdir],
                "exclusion_patterns": [],
                "max_file_size": 50_000_000,
            })

            await fi.run_scan()  # baseline

            # Add a new file
            new_file = Path(tmpdir) / "new.txt"
            new_file.write_text("new content")

            result = await fi.run_scan()
            assert str(new_file) in result["changes"]["added"]

    @pytest.mark.asyncio
    async def test_scan_detects_deleted_files(self):
        """Scan should detect deleted files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            to_delete = Path(tmpdir) / "to_delete.txt"
            to_delete.write_text("will be deleted")

            fi = FileIntegrity(config={
                "watched_paths": [tmpdir],
                "exclusion_patterns": [],
                "max_file_size": 50_000_000,
            })

            await fi.run_scan()  # baseline

            # Delete the file
            os.unlink(to_delete)

            result = await fi.run_scan()
            assert str(to_delete) in result["changes"]["deleted"]

    @pytest.mark.asyncio
    async def test_exclusion_patterns_applied(self):
        """Excluded files should not be included in scan."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "keep.py").write_text("keep")
            (Path(tmpdir) / "ignore.tmp").write_text("ignore")
            (Path(tmpdir) / "skip.log").write_text("skip")

            fi = FileIntegrity(config={
                "watched_paths": [tmpdir],
                "exclusion_patterns": ["*.tmp", "*.log"],
                "max_file_size": 50_000_000,
            })

            result = await fi.run_scan()
            assert result["files_scanned"] == 1  # only keep.py

    def test_get_baselines_not_established(self):
        """Should report baseline not established."""
        result = self.fi.get_baselines()
        assert result["established"] is False
        assert result["file_count"] == 0

    def test_get_last_scan_none(self):
        """Should return None when no scan has run."""
        assert self.fi.get_last_scan() is None

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        """Should start and stop cleanly."""
        await self.fi.start()
        assert self.fi.running is True
        assert self.fi.health_status == "running"

        await self.fi.stop()
        assert self.fi.running is False
        assert self.fi.health_status == "stopped"

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Health check should return relevant details."""
        health = await self.fi.health_check()
        assert health["status"] == "initialized"
        assert "baseline_files" in health["details"]
        assert "baseline_established" in health["details"]
        assert health["details"]["baseline_established"] is False
