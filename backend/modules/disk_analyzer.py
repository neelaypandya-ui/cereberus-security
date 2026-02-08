"""Disk analysis and cleanup utility for Cereberus.

On-demand system disk analyzer that identifies cleanable file categories,
finds large files, and executes safe cleanup operations on Windows systems.
Not a BaseModule subclass — invoked directly via API routes.
"""

import asyncio
import ctypes
import ctypes.wintypes
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..utils.logging import get_logger

logger = get_logger("modules.disk_analyzer")

# ---------------------------------------------------------------------------
# ctypes structures and constants for Recycle Bin operations
# ---------------------------------------------------------------------------

class SHQUERYRBINFO(ctypes.Structure):
    """Win32 SHQUERYRBINFO structure for SHQueryRecycleBinW."""
    _fields_ = [
        ("cbSize", ctypes.wintypes.DWORD),
        ("i64Size", ctypes.c_int64),
        ("i64NumItems", ctypes.c_int64),
    ]


# SHEmptyRecycleBin flags
SHERB_NOCONFIRMATION = 0x00000001
SHERB_NOPROGRESSUI = 0x00000002
SHERB_NOSOUND = 0x00000004

# Directories to skip when scanning for large files
SKIP_DIRS = {"AppData\\Local\\Packages", "node_modules", ".git", "__pycache__"}


class DiskAnalyzer:
    """Analyzes disk usage, identifies cleanable categories, and executes
    safe cleanup operations.  All heavy I/O is offloaded to a thread pool
    so the async event loop is never blocked."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="disk_analyzer")
        self._categories = self._build_categories()

    @property
    def known_categories(self) -> set[str]:
        """Return the set of valid category names."""
        return {c["name"] for c in self._categories}

    # ------------------------------------------------------------------
    # Category definitions
    # ------------------------------------------------------------------

    @staticmethod
    def _build_categories() -> list[dict]:
        """Return the list of cleanup category definitions."""
        return [
            {
                "name": "windows_temp",
                "description": "Windows system temporary files",
                "security_note": "Malware frequently stages payloads in system temp",
                "paths": [r"C:\Windows\Temp"],
            },
            {
                "name": "user_temp",
                "description": "Current user temporary files",
                "security_note": "Common malware drop location",
                "paths": [os.path.expandvars(r"%TEMP%")],
            },
            {
                "name": "prefetch",
                "description": "Windows Prefetch data",
                "security_note": "Reveals application execution history",
                "paths": [r"C:\Windows\Prefetch"],
            },
            {
                "name": "thumbnails",
                "description": "Explorer thumbnail cache files",
                "security_note": "May cache thumbnails of sensitive images",
                "paths": [
                    os.path.expandvars(
                        r"%LOCALAPPDATA%\Microsoft\Windows\Explorer"
                    )
                ],
                "pattern": "thumbcache_*",
            },
            {
                "name": "crash_dumps",
                "description": "Application and system crash dump files",
                "security_note": "May contain sensitive memory contents",
                "paths": [
                    os.path.expandvars(r"%LOCALAPPDATA%\CrashDumps"),
                    r"C:\ProgramData\Microsoft\Windows\WER",
                ],
            },
            {
                "name": "windows_update",
                "description": "Cached Windows Update packages",
                "security_note": "Old update packages consume significant space",
                "paths": [r"C:\Windows\SoftwareDistribution\Download"],
            },
            {
                "name": "recycle_bin",
                "description": "Windows Recycle Bin contents",
                "security_note": "Deleted sensitive files remain recoverable",
                "paths": [],  # handled via ctypes
            },
            {
                "name": "browser_cache",
                "description": "Web browser cached data (Chrome, Edge, Firefox)",
                "security_note": "May contain cached credentials and session tokens",
                "paths": [
                    os.path.expandvars(
                        r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\Cache_Data"
                    ),
                    os.path.expandvars(
                        r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\Cache_Data"
                    ),
                    # Firefox profiles resolved dynamically at scan time
                ],
                "_firefox_pattern": True,
            },
            {
                "name": "old_downloads",
                "description": "Download folder files older than 30 days",
                "security_note": "Stale downloads may include forgotten malware",
                "paths": [os.path.expandvars(r"%USERPROFILE%\Downloads")],
                "max_age_days": 30,
            },
            {
                "name": "log_files",
                "description": "System and application log files",
                "security_note": "Logs may contain sensitive operational data",
                "paths": [
                    os.path.expandvars(r"%TEMP%"),
                    r"C:\Windows\Temp",
                    r"C:\Windows\Logs",
                ],
                "pattern": "*.log",
            },
        ]

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def analyze(self) -> dict:
        """Scan all categories and return disk usage summary.

        Returns:
            {
                "disk_usage": {"total": int, "used": int, "free": int, "percent": float},
                "categories": [
                    {"name": str, "description": str, "security_note": str,
                     "size_bytes": int, "file_count": int}
                ],
                "total_cleanable_bytes": int,
            }
        """
        loop = asyncio.get_running_loop()

        # Disk usage ---------------------------------------------------------
        usage = shutil.disk_usage("C:\\")
        disk_usage = {
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": round((usage.used / usage.total) * 100, 1),
        }

        # Scan each category in the thread pool ------------------------------
        category_results: list[dict] = []
        total_cleanable = 0

        tasks = []
        for cat in self._categories:
            tasks.append(loop.run_in_executor(self._executor, self._scan_category, cat))

        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        for cat, result in zip(self._categories, scan_results):
            if isinstance(result, Exception):
                logger.warning(
                    "category_scan_error",
                    category=cat["name"],
                    error=str(result),
                )
                category_results.append({
                    "id": cat["name"],
                    "name": cat["name"],
                    "description": cat["description"],
                    "security_note": cat["security_note"],
                    "size_bytes": 0,
                    "file_count": 0,
                })
                continue

            size_bytes, file_count = result
            total_cleanable += size_bytes
            category_results.append({
                "id": cat["name"],
                "name": cat["name"],
                "description": cat["description"],
                "security_note": cat["security_note"],
                "size_bytes": size_bytes,
                "file_count": file_count,
            })

        return {
            "disk_usage": disk_usage,
            "categories": category_results,
            "total_cleanable_bytes": total_cleanable,
        }

    async def clean(self, categories: list[str]) -> dict:
        """Clean the specified categories.

        Args:
            categories: list of category name strings to clean.

        Returns:
            {
                "results": {
                    "<category>": {"freed_bytes": int, "files_deleted": int, "errors": list[str]}
                },
                "total_freed": int,
            }
        """
        loop = asyncio.get_running_loop()
        results: dict[str, dict] = {}
        total_freed = 0

        cat_map = {c["name"]: c for c in self._categories}

        tasks = []
        ordered_names: list[str] = []
        for name in categories:
            cat = cat_map.get(name)
            if cat is None:
                results[name] = {"freed_bytes": 0, "files_deleted": 0, "errors": [f"Unknown category: {name}"]}
                continue
            ordered_names.append(name)
            tasks.append(loop.run_in_executor(self._executor, self._clean_category, cat))

        clean_results = await asyncio.gather(*tasks, return_exceptions=True)

        for name, result in zip(ordered_names, clean_results):
            if isinstance(result, Exception):
                logger.error("category_clean_error", category=name, error=str(result))
                results[name] = {"freed_bytes": 0, "files_deleted": 0, "errors": [str(result)]}
                continue

            freed_bytes, deleted_count, errors = result
            total_freed += freed_bytes
            results[name] = {
                "freed_bytes": freed_bytes,
                "files_deleted": deleted_count,
                "errors": errors,
            }
            logger.info(
                "category_cleaned",
                category=name,
                freed_bytes=freed_bytes,
                files_deleted=deleted_count,
                error_count=len(errors),
            )

        return {"results": results, "total_freed": total_freed}

    async def find_large_files(self, min_size_mb: int = 100, limit: int = 20) -> list[dict]:
        """Find the largest files under the user's home directory.

        Skips ``AppData\\Local\\Packages``, ``node_modules``, ``.git``, and
        ``__pycache__`` to avoid slow traversal.

        Args:
            min_size_mb: minimum file size in megabytes.
            limit: maximum number of results to return.

        Returns:
            Sorted (descending) list of ``{path, size_bytes, modified, extension}``.
        """
        loop = asyncio.get_running_loop()
        min_size = min_size_mb * 1024 * 1024
        home = os.path.expandvars(r"%USERPROFILE%")
        results = await loop.run_in_executor(
            self._executor, self._collect_large_files, home, min_size, limit
        )
        return results

    # ------------------------------------------------------------------
    # Internal: scanning helpers
    # ------------------------------------------------------------------

    def _scan_category(self, cat: dict) -> tuple[int, int]:
        """Synchronous scan dispatcher for a single category."""
        name = cat["name"]

        if name == "recycle_bin":
            return self._get_recycle_bin_info()

        if name == "browser_cache":
            return self._scan_browser_cache(cat)

        pattern = cat.get("pattern")
        max_age_days = cat.get("max_age_days")

        total_bytes = 0
        total_count = 0
        for path in cat["paths"]:
            path = os.path.expandvars(path)
            if not os.path.isdir(path):
                continue
            b, c = self._scan_directory_size(path, pattern=pattern, max_age_days=max_age_days)
            total_bytes += b
            total_count += c

        return total_bytes, total_count

    def _scan_browser_cache(self, cat: dict) -> tuple[int, int]:
        """Scan browser cache directories including dynamic Firefox profiles."""
        total_bytes = 0
        total_count = 0

        # Chrome and Edge paths (already in cat["paths"])
        for path in cat["paths"]:
            path = os.path.expandvars(path)
            if not os.path.isdir(path):
                continue
            b, c = self._scan_directory_size(path)
            total_bytes += b
            total_count += c

        # Firefox profiles — dynamic glob
        ff_profiles = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
        if os.path.isdir(ff_profiles):
            try:
                for entry in os.scandir(ff_profiles):
                    if entry.is_dir(follow_symlinks=False):
                        cache_dir = os.path.join(entry.path, "cache2")
                        if os.path.isdir(cache_dir):
                            b, c = self._scan_directory_size(cache_dir)
                            total_bytes += b
                            total_count += c
            except (PermissionError, OSError):
                pass

        return total_bytes, total_count

    def _scan_directory_size(
        self,
        path: str,
        pattern: Optional[str] = None,
        max_age_days: Optional[int] = None,
    ) -> tuple[int, int]:
        """Walk *path* using ``os.scandir()``, summing file sizes.

        Args:
            path: directory to scan.
            pattern: optional glob-style filename pattern (e.g. ``*.log``,
                     ``thumbcache_*``).  If provided, only matching files are
                     counted.
            max_age_days: if set, only files older than this many days are
                          counted.

        Returns:
            ``(total_bytes, file_count)``
        """
        total_bytes = 0
        file_count = 0
        cutoff = time.time() - (max_age_days * 86400) if max_age_days else None

        dirs_to_scan = [path]
        while dirs_to_scan:
            current = dirs_to_scan.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                dirs_to_scan.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            if pattern and not self._match_pattern(entry.name, pattern):
                                continue
                            stat = entry.stat(follow_symlinks=False)
                            if cutoff and stat.st_mtime > cutoff:
                                continue
                            total_bytes += stat.st_size
                            file_count += 1
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue

        return total_bytes, file_count

    # ------------------------------------------------------------------
    # Internal: cleaning helpers
    # ------------------------------------------------------------------

    def _clean_category(self, cat: dict) -> tuple[int, int, list[str]]:
        """Synchronous clean dispatcher for a single category."""
        name = cat["name"]

        if name == "recycle_bin":
            return self._clean_recycle_bin()

        if name == "browser_cache":
            return self._clean_browser_cache(cat)

        pattern = cat.get("pattern")
        max_age_days = cat.get("max_age_days")

        total_freed = 0
        total_deleted = 0
        all_errors: list[str] = []

        for path in cat["paths"]:
            path = os.path.expandvars(path)
            if not os.path.isdir(path):
                continue
            freed, deleted, errors = self._clean_directory(
                path, pattern=pattern, max_age_days=max_age_days
            )
            total_freed += freed
            total_deleted += deleted
            all_errors.extend(errors)

        return total_freed, total_deleted, all_errors

    def _clean_browser_cache(self, cat: dict) -> tuple[int, int, list[str]]:
        """Clean browser cache directories including dynamic Firefox profiles."""
        total_freed = 0
        total_deleted = 0
        all_errors: list[str] = []

        # Chrome and Edge
        for path in cat["paths"]:
            path = os.path.expandvars(path)
            if not os.path.isdir(path):
                continue
            freed, deleted, errors = self._clean_directory(path)
            total_freed += freed
            total_deleted += deleted
            all_errors.extend(errors)

        # Firefox profiles
        ff_profiles = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
        if os.path.isdir(ff_profiles):
            try:
                for entry in os.scandir(ff_profiles):
                    if entry.is_dir(follow_symlinks=False):
                        cache_dir = os.path.join(entry.path, "cache2")
                        if os.path.isdir(cache_dir):
                            freed, deleted, errors = self._clean_directory(cache_dir)
                            total_freed += freed
                            total_deleted += deleted
                            all_errors.extend(errors)
            except (PermissionError, OSError):
                pass

        return total_freed, total_deleted, all_errors

    def _clean_directory(
        self,
        path: str,
        pattern: Optional[str] = None,
        max_age_days: Optional[int] = None,
    ) -> tuple[int, int, list[str]]:
        """Delete files inside *path*.

        Args:
            path: directory to clean.
            pattern: optional filename glob pattern.
            max_age_days: if set, only files older than this many days are
                          deleted.

        Returns:
            ``(freed_bytes, deleted_count, errors)``
        """
        freed_bytes = 0
        deleted_count = 0
        errors: list[str] = []
        cutoff = time.time() - (max_age_days * 86400) if max_age_days else None

        dirs_to_scan = [path]
        while dirs_to_scan:
            current = dirs_to_scan.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                # For browser_cache and similar categories we
                                # recurse into subdirs but only delete files.
                                dirs_to_scan.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            if pattern and not self._match_pattern(entry.name, pattern):
                                continue
                            stat = entry.stat(follow_symlinks=False)
                            if cutoff and stat.st_mtime > cutoff:
                                continue
                            size = stat.st_size
                            os.unlink(entry.path)
                            freed_bytes += size
                            deleted_count += 1
                        except (PermissionError, OSError) as exc:
                            errors.append(f"{entry.path}: {exc}")
            except (PermissionError, OSError) as exc:
                errors.append(f"{current}: {exc}")

        return freed_bytes, deleted_count, errors

    def _clean_recycle_bin(self) -> tuple[int, int, list[str]]:
        """Empty the Recycle Bin and report freed space."""
        errors: list[str] = []
        size_bytes, item_count = self._get_recycle_bin_info()

        if item_count == 0:
            return 0, 0, []

        success = self._empty_recycle_bin()
        if not success:
            errors.append("SHEmptyRecycleBinW returned a non-zero HRESULT")
            return 0, 0, errors

        logger.info(
            "recycle_bin_emptied",
            freed_bytes=size_bytes,
            items=item_count,
        )
        return size_bytes, item_count, errors

    # ------------------------------------------------------------------
    # Recycle Bin ctypes helpers
    # ------------------------------------------------------------------

    def _get_recycle_bin_info(self) -> tuple[int, int]:
        """Query the Recycle Bin size and item count via SHQueryRecycleBinW.

        Returns:
            ``(size_bytes, item_count)``
        """
        info = SHQUERYRBINFO()
        info.cbSize = ctypes.sizeof(SHQUERYRBINFO)

        try:
            hr = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
            if hr != 0:
                logger.warning("recycle_bin_query_failed", hresult=hr)
                return 0, 0
            return info.i64Size, info.i64NumItems
        except (OSError, AttributeError) as exc:
            logger.warning("recycle_bin_query_error", error=str(exc))
            return 0, 0

    def _empty_recycle_bin(self) -> bool:
        """Empty the Recycle Bin silently via SHEmptyRecycleBinW.

        Uses ``SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND``.

        Returns:
            ``True`` on success.
        """
        flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
        try:
            hr = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags)
            if hr != 0:
                logger.warning("recycle_bin_empty_failed", hresult=hr)
                return False
            return True
        except (OSError, AttributeError) as exc:
            logger.warning("recycle_bin_empty_error", error=str(exc))
            return False

    # ------------------------------------------------------------------
    # Large file finder
    # ------------------------------------------------------------------

    def _collect_large_files(
        self, root: str, min_size: int, limit: int
    ) -> list[dict]:
        """Recursively find the largest files under *root*.

        Skips directories listed in ``SKIP_DIRS``.
        """
        large_files: list[dict] = []

        dirs_to_scan = [root]
        while dirs_to_scan:
            current = dirs_to_scan.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                # Check if this dir should be skipped.
                                rel = os.path.relpath(entry.path, root)
                                if any(skip in rel for skip in SKIP_DIRS):
                                    continue
                                dirs_to_scan.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            stat = entry.stat(follow_symlinks=False)
                            if stat.st_size >= min_size:
                                _, ext = os.path.splitext(entry.name)
                                large_files.append({
                                    "path": entry.path,
                                    "size_bytes": stat.st_size,
                                    "modified": datetime.fromtimestamp(
                                        stat.st_mtime, tz=timezone.utc
                                    ).isoformat(),
                                    "extension": ext.lower() if ext else "",
                                })
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue

        # Sort descending by size and trim to limit
        large_files.sort(key=lambda f: f["size_bytes"], reverse=True)
        return large_files[:limit]

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _match_pattern(filename: str, pattern: str) -> bool:
        """Simple glob-style pattern matching supporting leading and trailing
        wildcards (``*``).  Covers patterns like ``*.log`` and
        ``thumbcache_*``."""
        lower_name = filename.lower()
        lower_pattern = pattern.lower()

        if lower_pattern.startswith("*") and lower_pattern.endswith("*"):
            return lower_pattern[1:-1] in lower_name
        if lower_pattern.startswith("*"):
            return lower_name.endswith(lower_pattern[1:])
        if lower_pattern.endswith("*"):
            return lower_name.startswith(lower_pattern[:-1])
        return lower_name == lower_pattern
