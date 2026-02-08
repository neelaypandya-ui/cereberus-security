"""Database backup manager — SQLite file-level backup and restore."""

import os
import shutil
from datetime import datetime, timezone

from ..utils.logging import get_logger

logger = get_logger("maintenance.backup")


class BackupManager:
    """Manages SQLite database backups via file copy."""

    def __init__(
        self,
        db_path: str = "cereberus.db",
        backup_dir: str = "backups",
    ):
        self._db_path = db_path
        self._backup_dir = backup_dir

    def _ensure_backup_dir(self) -> None:
        """Create the backup directory if it does not exist."""
        os.makedirs(self._backup_dir, exist_ok=True)

    def backup_database(self) -> dict:
        """Create a timestamped backup of the SQLite database file.

        Returns:
            dict with keys: path, size, timestamp
        """
        self._ensure_backup_dir()

        if not os.path.exists(self._db_path):
            raise FileNotFoundError(f"Database file not found: {self._db_path}")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        backup_name = f"cereberus-{timestamp}.db"
        backup_path = os.path.join(self._backup_dir, backup_name)

        shutil.copy2(self._db_path, backup_path)

        size = os.path.getsize(backup_path)
        logger.info(
            "database_backup_created",
            path=backup_path,
            size=size,
            timestamp=timestamp,
        )

        return {
            "path": backup_path,
            "size": size,
            "timestamp": timestamp,
        }

    def list_backups(self) -> list[dict]:
        """List all available backup files with metadata.

        Returns:
            List of dicts with keys: name, path, size, timestamp
        """
        self._ensure_backup_dir()

        backups = []
        for filename in sorted(os.listdir(self._backup_dir), reverse=True):
            if filename.startswith("cereberus-") and filename.endswith(".db"):
                filepath = os.path.join(self._backup_dir, filename)
                stat = os.stat(filepath)
                backups.append({
                    "name": filename,
                    "path": filepath,
                    "size": stat.st_size,
                    "timestamp": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                })

        return backups

    def restore_from_backup(self, backup_name: str) -> dict:
        """Restore the database from a named backup file.

        WARNING: This overwrites the current database file.

        Args:
            backup_name: Filename of the backup (e.g. 'cereberus-20260207-120000.db')

        Returns:
            dict with keys: restored_from, size, timestamp
        """
        backup_path = os.path.join(self._backup_dir, backup_name)

        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        shutil.copy2(backup_path, self._db_path)

        size = os.path.getsize(self._db_path)
        logger.warning(
            "database_restored_from_backup",
            backup=backup_name,
            size=size,
        )

        return {
            "restored_from": backup_name,
            "size": size,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
