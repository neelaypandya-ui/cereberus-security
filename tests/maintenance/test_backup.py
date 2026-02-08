"""Tests for BackupManager — SQLite file-level backup, listing, and restore."""

import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from backend.maintenance.backup import BackupManager


class TestBackupCreatesFile:
    def test_backup_creates_file(self):
        """backup_database() should copy the DB file to a timestamped backup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake database file
            db_path = os.path.join(tmpdir, "cereberus.db")
            with open(db_path, "wb") as f:
                f.write(b"SQLite format 3\x00" + b"\x00" * 100)

            backup_dir = os.path.join(tmpdir, "backups")

            manager = BackupManager(db_path=db_path, backup_dir=backup_dir)

            result = manager.backup_database()

            # Verify the backup file exists
            assert os.path.exists(result["path"])
            assert result["size"] > 0
            assert result["timestamp"] is not None

            # Verify the backup directory was created
            assert os.path.isdir(backup_dir)

            # Verify the backup file has the correct content
            with open(result["path"], "rb") as f:
                content = f.read()
            assert content.startswith(b"SQLite format 3\x00")


class TestListBackups:
    def test_list_backups(self):
        """list_backups() should return a sorted list of backup files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "cereberus.db")
            with open(db_path, "wb") as f:
                f.write(b"fake-db-content")

            backup_dir = os.path.join(tmpdir, "backups")
            os.makedirs(backup_dir)

            # Create some fake backup files
            for name in [
                "cereberus-20260201-100000.db",
                "cereberus-20260205-120000.db",
                "cereberus-20260207-080000.db",
            ]:
                path = os.path.join(backup_dir, name)
                with open(path, "wb") as f:
                    f.write(b"backup-data")

            # Also create a non-backup file that should be ignored
            with open(os.path.join(backup_dir, "readme.txt"), "w") as f:
                f.write("not a backup")

            manager = BackupManager(db_path=db_path, backup_dir=backup_dir)

            backups = manager.list_backups()

            assert len(backups) == 3
            # Should be sorted in reverse chronological order
            assert backups[0]["name"] == "cereberus-20260207-080000.db"
            assert backups[1]["name"] == "cereberus-20260205-120000.db"
            assert backups[2]["name"] == "cereberus-20260201-100000.db"

            # Each entry should have required fields
            for backup in backups:
                assert "name" in backup
                assert "path" in backup
                assert "size" in backup
                assert "timestamp" in backup


class TestRestoreFromBackup:
    def test_restore_from_backup(self):
        """restore_from_backup() should copy the backup file over the current DB."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a "current" database
            db_path = os.path.join(tmpdir, "cereberus.db")
            with open(db_path, "wb") as f:
                f.write(b"current-db-content")

            # Create a backup to restore from
            backup_dir = os.path.join(tmpdir, "backups")
            os.makedirs(backup_dir)
            backup_name = "cereberus-20260205-120000.db"
            backup_path = os.path.join(backup_dir, backup_name)
            with open(backup_path, "wb") as f:
                f.write(b"backup-db-content-to-restore")

            manager = BackupManager(db_path=db_path, backup_dir=backup_dir)

            result = manager.restore_from_backup(backup_name)

            # Verify the current DB file now has the backup content
            with open(db_path, "rb") as f:
                content = f.read()
            assert content == b"backup-db-content-to-restore"

            assert result["restored_from"] == backup_name
            assert result["size"] == len(b"backup-db-content-to-restore")
            assert result["timestamp"] is not None
