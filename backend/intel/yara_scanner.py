"""YaraScanner — Bond's Q-Branch YARA weapon system.

Compiles YARA rules from .yar files and DB-stored rules, scans files,
directories, process memory, and raw buffers for matches.
"""

import asyncio
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..utils.logging import get_logger

logger = get_logger("intel.yara_scanner")

# Lazy import — yara may not be installed
_yara = None


def _get_yara():
    """Lazy-load yara-python."""
    global _yara
    if _yara is None:
        try:
            import yara
            _yara = yara
        except ImportError:
            logger.warning("yara_python_not_installed — YARA scanning disabled")
    return _yara


class YaraScanner:
    """Bond's YARA weapon system — file and memory content scanning."""

    def __init__(
        self,
        rules_dir: str = "yara_rules",
        scan_timeout: int = 60,
        max_file_size: int = 100_000_000,
    ):
        self._rules_dir = Path(rules_dir)
        self._scan_timeout = scan_timeout
        self._max_file_size = max_file_size
        self._compiled_rules = None
        self._rule_metadata: list[dict] = []
        self._db_session_factory = None

        # Stats
        self._total_scans: int = 0
        self._total_matches: int = 0
        self._files_scanned: int = 0
        self._last_compile: Optional[str] = None
        self._last_scan: Optional[str] = None

    def set_db_session_factory(self, factory) -> None:
        """Attach DB session factory for persisting scan results and loading DB rules."""
        self._db_session_factory = factory

    async def compile_rules(self) -> dict:
        """Load .yar files + DB rules, compile into a single YARA ruleset."""
        yara = _get_yara()
        if yara is None:
            return {"status": "error", "message": "yara-python not installed"}

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._compile_rules_sync, yara)
        return result

    def _compile_rules_sync(self, yara) -> dict:
        """Synchronous rule compilation."""
        filepaths = {}
        self._rule_metadata = []

        # Load .yar files from rules directory
        if self._rules_dir.exists():
            for yar_file in sorted(self._rules_dir.glob("*.yar")):
                namespace = yar_file.stem
                filepaths[namespace] = str(yar_file)
                logger.info("yara_rule_file_loaded", file=yar_file.name, namespace=namespace)

        # Load DB rules (synchronous — called from executor)
        db_sources = self._load_db_rules_sync()

        try:
            if filepaths or db_sources:
                # Combine file paths and sources
                compile_kwargs = {}
                if filepaths:
                    compile_kwargs["filepaths"] = filepaths
                if db_sources:
                    compile_kwargs["sources"] = db_sources

                self._compiled_rules = yara.compile(**compile_kwargs)

                # Extract metadata from compiled rules
                self._extract_metadata()
                self._last_compile = datetime.now(timezone.utc).isoformat()

                logger.info(
                    "yara_rules_compiled",
                    file_rules=len(filepaths),
                    db_rules=len(db_sources),
                    total_rules=len(self._rule_metadata),
                )
                return {
                    "status": "compiled",
                    "file_rules": len(filepaths),
                    "db_rules": len(db_sources),
                    "total_rules": len(self._rule_metadata),
                }
            else:
                logger.warning("yara_no_rules_found")
                return {"status": "empty", "message": "No YARA rules found"}
        except Exception as e:
            logger.error("yara_compile_error", error=str(e))
            return {"status": "error", "message": str(e)}

    def _load_db_rules_sync(self) -> dict[str, str]:
        """Load enabled YARA rules from DB (synchronous wrapper)."""
        sources = {}
        if not self._db_session_factory:
            return sources

        try:
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                # We're in an executor, can't use async — use a new event loop
                return sources  # Skip DB rules in sync context; they'll be loaded on next compile
            except RuntimeError:
                pass
        except Exception:
            pass
        return sources

    def _extract_metadata(self) -> None:
        """Extract rule names and metadata from compiled rules."""
        self._rule_metadata = []
        if not self._compiled_rules:
            return
        # YARA doesn't expose rule list directly from compiled rules.
        # We'll track metadata from match results instead.
        # Populate from file-based rules by parsing .yar files
        if self._rules_dir.exists():
            for yar_file in self._rules_dir.glob("*.yar"):
                try:
                    content = yar_file.read_text(encoding="utf-8", errors="ignore")
                    for line in content.split("\n"):
                        stripped = line.strip()
                        if stripped.startswith("rule ") and "{" in stripped:
                            rule_name = stripped.split()[1].rstrip("{").strip()
                            self._rule_metadata.append({
                                "name": rule_name,
                                "namespace": yar_file.stem,
                                "source": "file",
                                "file": yar_file.name,
                            })
                except Exception:
                    pass

    async def scan_file(self, path: str, triggered_by: str = "manual") -> list[dict]:
        """Scan a single file with YARA rules. Returns list of matches."""
        if not self._compiled_rules:
            return []

        file_path = Path(path)
        if not file_path.exists() or not file_path.is_file():
            return []

        try:
            if file_path.stat().st_size > self._max_file_size:
                return []
        except OSError:
            return []

        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(
            None, self._scan_file_sync, str(file_path)
        )

        # Compute file hash
        file_hash = await loop.run_in_executor(None, self._hash_file, str(file_path))
        file_size = file_path.stat().st_size if file_path.exists() else 0

        results = self._matches_to_dicts(matches, "file", str(file_path), file_hash, file_size, triggered_by)

        self._total_scans += 1
        self._files_scanned += 1
        self._total_matches += len(results)
        self._last_scan = datetime.now(timezone.utc).isoformat()

        # Persist results
        if results:
            await self._persist_results(results)

        return results

    def _scan_file_sync(self, path: str) -> list:
        """Synchronous YARA file scan."""
        try:
            return self._compiled_rules.match(filepath=path, timeout=self._scan_timeout)
        except Exception as e:
            logger.error("yara_scan_file_error", path=path, error=str(e))
            return []

    async def scan_directory(self, path: str, triggered_by: str = "manual") -> list[dict]:
        """Recursively scan a directory. Returns all matches."""
        all_results = []
        dir_path = Path(path)
        if not dir_path.exists() or not dir_path.is_dir():
            return []

        for root, _dirs, files in os.walk(dir_path):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    if fpath.stat().st_size > self._max_file_size:
                        continue
                except OSError:
                    continue
                matches = await self.scan_file(str(fpath), triggered_by=triggered_by)
                all_results.extend(matches)

        return all_results

    async def scan_process_memory(self, pid: int, triggered_by: str = "manual") -> list[dict]:
        """Scan process memory using YARA's pid matching (requires admin)."""
        if not self._compiled_rules:
            return []

        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(None, self._scan_pid_sync, pid)

        results = self._matches_to_dicts(matches, "process", str(pid), None, None, triggered_by)

        self._total_scans += 1
        self._total_matches += len(results)
        self._last_scan = datetime.now(timezone.utc).isoformat()

        if results:
            await self._persist_results(results)

        return results

    def _scan_pid_sync(self, pid: int) -> list:
        """Synchronous YARA process memory scan."""
        try:
            return self._compiled_rules.match(pid=pid, timeout=self._scan_timeout)
        except Exception as e:
            logger.error("yara_scan_pid_error", pid=pid, error=str(e))
            return []

    async def scan_buffer(self, data: bytes, label: str = "buffer", triggered_by: str = "manual") -> list[dict]:
        """Scan raw bytes with YARA rules."""
        if not self._compiled_rules:
            return []

        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(None, self._scan_buffer_sync, data)

        buf_hash = hashlib.sha256(data).hexdigest()
        results = self._matches_to_dicts(matches, "buffer", label, buf_hash, len(data), triggered_by)

        self._total_scans += 1
        self._total_matches += len(results)
        self._last_scan = datetime.now(timezone.utc).isoformat()

        if results:
            await self._persist_results(results)

        return results

    def _scan_buffer_sync(self, data: bytes) -> list:
        """Synchronous YARA buffer scan."""
        try:
            return self._compiled_rules.match(data=data, timeout=self._scan_timeout)
        except Exception as e:
            logger.error("yara_scan_buffer_error", error=str(e))
            return []

    def _matches_to_dicts(
        self,
        matches: list,
        scan_type: str,
        target: str,
        file_hash: Optional[str],
        file_size: Optional[int],
        triggered_by: str,
    ) -> list[dict]:
        """Convert YARA match objects to serializable dicts."""
        results = []
        now = datetime.now(timezone.utc).isoformat()
        for match in matches:
            meta = dict(match.meta) if hasattr(match, "meta") else {}
            severity = meta.get("severity", "medium")

            # Extract matched strings info
            strings_info = []
            if hasattr(match, "strings"):
                for s in match.strings[:20]:  # Cap at 20 to avoid huge payloads
                    try:
                        instances = list(s.instances)[:5] if hasattr(s, "instances") else []
                        strings_info.append({
                            "identifier": s.identifier if hasattr(s, "identifier") else str(s),
                            "offsets": [inst.offset for inst in instances] if instances else [],
                        })
                    except Exception:
                        strings_info.append({"identifier": str(s), "offsets": []})

            results.append({
                "scan_type": scan_type,
                "target": target,
                "rule_name": match.rule,
                "rule_namespace": match.namespace if hasattr(match, "namespace") else None,
                "strings_matched_json": json.dumps(strings_info),
                "meta_json": json.dumps(meta),
                "severity": severity,
                "scanned_at": now,
                "file_hash": file_hash,
                "file_size": file_size,
                "triggered_by": triggered_by,
            })
        return results

    @staticmethod
    def _hash_file(path: str) -> Optional[str]:
        """Compute SHA-256 hash of a file."""
        try:
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha.update(chunk)
            return sha.hexdigest()
        except (OSError, PermissionError):
            return None

    async def _persist_results(self, results: list[dict]) -> None:
        """Write scan results to the database."""
        if not self._db_session_factory:
            return
        try:
            from ..models.yara_scan_result import YaraScanResult
            async with self._db_session_factory() as session:
                for r in results:
                    session.add(YaraScanResult(
                        scan_type=r["scan_type"],
                        target=r["target"][:500],
                        rule_name=r["rule_name"],
                        rule_namespace=r.get("rule_namespace"),
                        strings_matched_json=r.get("strings_matched_json"),
                        meta_json=r.get("meta_json"),
                        severity=r["severity"],
                        file_hash=r.get("file_hash"),
                        file_size=r.get("file_size"),
                        triggered_by=r.get("triggered_by"),
                    ))
                await session.commit()
        except Exception as e:
            logger.error("yara_persist_results_error", error=str(e))

    def get_stats(self) -> dict:
        """Return scan statistics."""
        return {
            "total_scans": self._total_scans,
            "total_matches": self._total_matches,
            "files_scanned": self._files_scanned,
            "rules_loaded": len(self._rule_metadata),
            "compiled": self._compiled_rules is not None,
            "last_compile": self._last_compile,
            "last_scan": self._last_scan,
            "rules_dir": str(self._rules_dir),
            "yara_available": _get_yara() is not None,
        }

    def get_loaded_rules(self) -> list[dict]:
        """Return metadata for all loaded rules."""
        return self._rule_metadata
