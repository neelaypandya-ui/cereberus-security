"""Commander Bond Module -- autonomous threat intelligence operative.

Scans open-source threat feeds on a schedule to identify new vulnerabilities,
malware samples, C2 infrastructure, and IOCs. Reports are delivered in Bond's
voice: precise, understated, lethally calm.

Phase 15: Bond gains SwordProtocol (autonomous response), OverwatchProtocol
(system integrity monitoring), and integration with YARA, MemoryScanner,
EventBus, and RemediationEngine.

Data sources (all free, no API keys required):
  - CISA Known Exploited Vulnerabilities (KEV)
  - NVD CVE 2.0 API (recent high-severity CVEs)
  - URLhaus (recent malware URLs)
  - Feodo Tracker (botnet C2 IPs)
  - ThreatFox (recent IOCs)
  - MalwareBazaar (recent malware samples)
"""

import asyncio
import hashlib
import json
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import aiohttp

from .base_module import BaseModule
from ..utils.logging import get_logger


# ---------------------------------------------------------------------------
# IntelligenceBrain — adaptive learning engine (Phase 14 Track 2)
# ---------------------------------------------------------------------------

class IntelligenceBrain:
    """Tracks feed quality and adapts scan behaviour based on threat velocity.

    Responsibilities:
    - Per-source quality scoring (relevance, freshness, severity, FP rate)
    - Adaptive scan interval based on threat velocity
    - Cross-feed IOC correlation (multi-source = higher confidence)
    - Relevance feedback loop (learn from irrelevant marks)
    """

    _MIN_INTERVAL: int = 3600       # 1 hour floor
    _MAX_INTERVAL: int = 43200      # 12 hour ceiling
    _DEFAULT_INTERVAL: int = 21600  # 6 hours

    def __init__(self) -> None:
        self.generation: int = 0

        # Per-source quality tracking: source_name -> metrics
        self._source_metrics: dict[str, dict] = {}
        for src in ("CISA KEV", "NVD", "URLhaus", "Feodo Tracker", "ThreatFox", "MalwareBazaar"):
            self._source_metrics[src] = {
                "total": 0,
                "relevant": 0,
                "false_positive": 0,
                "severity_sum": 0.0,
                "quality_score": 50.0,
            }

        # Cross-feed correlation: ioc_value -> set of source names
        self._ioc_sources: dict[str, set[str]] = {}
        self._correlations_found: int = 0

        # Threat velocity tracking
        self._recent_threat_counts: deque[tuple[datetime, int]] = deque(maxlen=20)
        self._adaptive_interval: int = self._DEFAULT_INTERVAL
        self._threat_trend: str = "stable"  # "rising", "stable", "falling"

        # Irrelevant feedback tracking
        self._irrelevant_ids: set[str] = set()

    # -- Source quality scoring --

    def record_findings(self, source: str, findings: list[dict]) -> None:
        """Record findings from a source for quality scoring."""
        metrics = self._source_metrics.get(source)
        if not metrics:
            return

        metrics["total"] += len(findings)

        severity_weights = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}
        for f in findings:
            sev = f.get("severity", "low")
            metrics["severity_sum"] += severity_weights.get(sev, 1.0)
            metrics["relevant"] += 1  # All new findings are assumed relevant initially

            # Cross-feed correlation: track IOCs across sources
            for ioc in f.get("iocs", []):
                if ioc not in self._ioc_sources:
                    self._ioc_sources[ioc] = set()
                prev_count = len(self._ioc_sources[ioc])
                self._ioc_sources[ioc].add(source)
                if len(self._ioc_sources[ioc]) > 1 and prev_count < len(self._ioc_sources[ioc]):
                    self._correlations_found += 1

        self._recalculate_quality(source)

    def mark_irrelevant(self, threat_id: str, source: str) -> None:
        """Feedback: mark a threat as irrelevant, penalizing source quality."""
        self._irrelevant_ids.add(threat_id)
        metrics = self._source_metrics.get(source)
        if metrics and metrics["relevant"] > 0:
            metrics["relevant"] -= 1
            metrics["false_positive"] += 1
            self._recalculate_quality(source)

    def _recalculate_quality(self, source: str) -> None:
        """Recalculate quality score for a source: (relevant / total) * severity_factor * (1 - fp_rate)."""
        m = self._source_metrics.get(source)
        if not m or m["total"] == 0:
            return

        relevance_ratio = m["relevant"] / m["total"]
        severity_factor = min(m["severity_sum"] / max(m["total"], 1), 4.0) / 4.0
        fp_rate = m["false_positive"] / m["total"]
        m["quality_score"] = round(max(0, min(100, relevance_ratio * (1 - fp_rate) * (0.5 + 0.5 * severity_factor) * 100)), 1)

    # -- Adaptive scan interval --

    def update_threat_velocity(self, threat_count: int) -> int:
        """Record threat count and return updated adaptive scan interval."""
        now = datetime.now(timezone.utc)
        self._recent_threat_counts.append((now, threat_count))
        self.generation += 1

        if len(self._recent_threat_counts) < 2:
            return self._adaptive_interval

        # Calculate velocity: threats per hour over recent scans
        counts = list(self._recent_threat_counts)
        time_span = (counts[-1][0] - counts[0][0]).total_seconds()
        if time_span <= 0:
            return self._adaptive_interval

        total_threats = sum(c[1] for c in counts)
        threats_per_hour = (total_threats / time_span) * 3600

        # Determine trend
        if len(counts) >= 3:
            recent = sum(c[1] for c in counts[-3:])
            earlier = sum(c[1] for c in counts[:3])
            if recent > earlier * 1.5:
                self._threat_trend = "rising"
            elif recent < earlier * 0.5:
                self._threat_trend = "falling"
            else:
                self._threat_trend = "stable"

        # Adaptive interval: more threats = shorter interval
        if threats_per_hour > 10:
            self._adaptive_interval = self._MIN_INTERVAL  # 1 hour
        elif threats_per_hour > 5:
            self._adaptive_interval = 7200  # 2 hours
        elif threats_per_hour > 1:
            self._adaptive_interval = 14400  # 4 hours
        elif threats_per_hour > 0:
            self._adaptive_interval = self._DEFAULT_INTERVAL  # 6 hours
        else:
            self._adaptive_interval = self._MAX_INTERVAL  # 12 hours

        return self._adaptive_interval

    # -- Cross-feed correlation --

    def get_correlated_iocs(self) -> list[dict]:
        """Return IOCs seen in multiple feeds (high-confidence)."""
        results = []
        for ioc, sources in self._ioc_sources.items():
            if len(sources) > 1:
                results.append({
                    "ioc": ioc,
                    "sources": sorted(sources),
                    "source_count": len(sources),
                    "confidence": min(100, 50 + len(sources) * 20),
                })
        return sorted(results, key=lambda x: x["source_count"], reverse=True)[:50]

    # -- Status export --

    def get_intelligence(self) -> dict:
        """Return intelligence metrics for API/frontend."""
        rankings = sorted(
            self._source_metrics.items(),
            key=lambda kv: kv[1]["quality_score"],
            reverse=True,
        )
        return {
            "generation": self.generation,
            "source_rankings": [name for name, _ in rankings],
            "source_scores": {
                name: {k: v for k, v in metrics.items()}
                for name, metrics in self._source_metrics.items()
            },
            "threat_trend": self._threat_trend,
            "adaptive_interval": self._adaptive_interval,
            "correlations_found": self._correlations_found,
            "total_threats_analyzed": sum(m["total"] for m in self._source_metrics.values()),
        }

# ---------------------------------------------------------------------------
# Feed endpoints
# ---------------------------------------------------------------------------
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
FEODO_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"

# ---------------------------------------------------------------------------
# Severity labels -- Bond style
# ---------------------------------------------------------------------------
SEVERITY_LABELS = {
    "critical": "License to kill -- immediate action required",
    "high": "Marked for elimination",
    "medium": "Under surveillance",
    "low": "Noted in the dossier",
}

logger = get_logger("module.commander_bond")


class CommanderBond(BaseModule):
    """Autonomous threat intelligence operative that scans open-source feeds.

    Periodically fetches data from six free threat intelligence sources,
    deduplicates findings, and produces Bond-style intelligence briefings
    complete with Cereberus-specific remediation prompts.
    """

    def __init__(self, config: dict | None = None):
        super().__init__(name="commander_bond", config=config)

        cfg = config or {}
        self._scan_interval: int = cfg.get("scan_interval", 21600)  # 6 hours
        self._reports: deque[dict] = deque(maxlen=30)
        self._last_scan: Optional[datetime] = None
        self._known_cve_ids: set[str] = set()
        self._known_ioc_hashes: set[str] = set()
        self._http_session: Optional[aiohttp.ClientSession] = None
        self._scan_task: Optional[asyncio.Task] = None
        self._alert_manager = None

        # Phase 14: IntelligenceBrain — adaptive learning
        self._brain = IntelligenceBrain()

        # Phase 14: Guardian protocol — overseer for Agent Smith
        self._guardian_task: Optional[asyncio.Task] = None
        self._agent_smith = None  # Set externally via set_agent_smith()
        self._containment_level: int = 0  # 0=GREEN, 1=YELLOW, 2=ORANGE, 3=RED
        self._containment_names = {0: "GREEN", 1: "YELLOW", 2: "ORANGE", 3: "RED"}
        self._stability_score: float = 100.0
        self._guardian_interventions: deque[dict] = deque(maxlen=50)
        self._lockdown_at: Optional[str] = None
        self._last_guardian_check: Optional[str] = None
        self._smith_prev_stats: Optional[dict] = None  # Previous Smith stats for delta tracking

        # Feed limits — configurable via CereberusConfig
        try:
            from ..dependencies import get_app_config
            _app_cfg = get_app_config()
            self._cisa_limit: int = getattr(_app_cfg, "bond_cisa_limit", 30)
            self._nvd_limit: int = getattr(_app_cfg, "bond_nvd_limit", 20)
            self._urlhaus_limit: int = getattr(_app_cfg, "bond_urlhaus_limit", 20)
            self._feodo_limit: int = getattr(_app_cfg, "bond_feodo_limit", 20)
            self._threatfox_limit: int = getattr(_app_cfg, "bond_threatfox_limit", 15)
        except Exception:
            self._cisa_limit = 30
            self._nvd_limit = 20
            self._urlhaus_limit = 20
            self._feodo_limit = 20
            self._threatfox_limit = 15

        # Running counters
        self._total_scans: int = 0
        self._total_threats_found: int = 0
        self._report_sequence: int = 0
        self._scanning: bool = False

        # Neutralized threat IDs — filtered out of all responses
        self._neutralized_ids: set[str] = set()

        # Phase 15: Sword Protocol — autonomous response
        self._sword = SwordProtocol()
        self._remediation_engine = None
        self._event_bus = None
        self._db_session_factory = None
        self._yara_scanner = None
        self._memory_scanner = None
        self._overwatch_task: Optional[asyncio.Task] = None

        # Phase 15: Overwatch Protocol — system integrity
        self._overwatch = OverwatchProtocol()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def set_agent_smith(self, smith) -> None:
        """Attach Agent Smith reference for Guardian oversight."""
        self._agent_smith = smith
        self.logger.info("commander_bond_guardian_attached")

    async def start(self) -> None:
        """Start the intelligence gathering loop."""
        self.running = True
        self.health_status = "running"
        self.logger.info("commander_bond_starting", status="Bond is in the field...")

        self._http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"User-Agent": "Cereberus-CommanderBond/1.0"},
        )

        # Execute an initial scan immediately
        await self._execute_scan()

        # Start the recurring scan loop
        self._scan_task = asyncio.create_task(self._scan_loop())

        # Start Guardian oversight loop if Smith is attached
        if self._agent_smith is not None:
            self._guardian_task = asyncio.create_task(self._guardian_loop())
            self.logger.info("guardian_loop_started")

        # Phase 15: Compute Overwatch baselines
        try:
            baseline_info = self._overwatch.compute_baselines()
            self.logger.info("overwatch_baselines_ready", **baseline_info)
        except Exception as e:
            self.logger.error("overwatch_baseline_failed", error=str(e))

        # Phase 15: Load Sword policies from DB
        if self._db_session_factory:
            try:
                await self._sword.load_policies(self._db_session_factory)
            except Exception as e:
                self.logger.error("sword_policy_load_failed", error=str(e))

        # Phase 15: Subscribe to EventBus for Sword Protocol evaluation
        if self._event_bus:
            self._event_bus.subscribe("*", self._sword_evaluate)
            self.logger.info("sword_event_bus_subscribed")

        # Phase 15: Start Overwatch periodic loop
        self._overwatch_task = asyncio.create_task(self._overwatch_loop())

        self.heartbeat()
        self.logger.info("commander_bond_started", status="Intelligence gathered")

    async def stop(self) -> None:
        """Recall the operative from the field."""
        self.running = False
        for task in (self._scan_task, self._guardian_task, self._overwatch_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
            self._http_session = None
        self.health_status = "stopped"
        self.logger.info("commander_bond_stopped", status="Bond has returned to MI6")

    async def health_check(self) -> dict:
        """Return module health status."""
        self.heartbeat()
        latest = self.get_latest_report()
        return {
            "status": self.health_status,
            "details": {
                "total_scans": self._total_scans,
                "total_threats_found": self._total_threats_found,
                "reports_buffered": len(self._reports),
                "last_scan": self._last_scan.isoformat() if self._last_scan else None,
                "latest_threat_count": latest["threat_count"] if latest else 0,
            },
        }

    # ------------------------------------------------------------------
    # External integrations
    # ------------------------------------------------------------------

    def set_alert_manager(self, manager) -> None:
        """Attach an AlertManager for auto-creating CRITICAL alerts."""
        self._alert_manager = manager
        self.logger.info("commander_bond_alert_manager_attached")

    # Phase 15: New component references
    def set_yara_scanner(self, scanner) -> None:
        """Attach YARA scanner — Bond's Q-Branch arsenal."""
        self._yara_scanner = scanner
        self.logger.info("commander_bond_yara_attached")

    def set_memory_scanner(self, scanner) -> None:
        """Attach Memory Scanner — Bond's reconnaissance."""
        self._memory_scanner = scanner
        self.logger.info("commander_bond_memory_scanner_attached")

    def set_remediation_engine(self, engine) -> None:
        """Attach RemediationEngine — Bond's weapons."""
        self._remediation_engine = engine
        self.logger.info("commander_bond_remediation_engine_attached")

    def set_event_bus(self, bus) -> None:
        """Attach EventBus — Bond's ears."""
        self._event_bus = bus
        self.logger.info("commander_bond_event_bus_attached")

    def set_db_session_factory(self, factory) -> None:
        """Attach DB session factory for Sword Protocol persistence."""
        self._db_session_factory = factory
        self.logger.info("commander_bond_db_factory_attached")

    # Sword Protocol public API
    def sword_enable(self) -> None:
        self._sword.enable()

    def sword_disable(self) -> None:
        self._sword.disable()

    def sword_lockout(self) -> None:
        self._sword.lockout()

    def sword_clear_lockout(self) -> None:
        self._sword.clear_lockout()

    def get_sword_stats(self) -> dict:
        return self._sword.get_stats()

    def sword_test_policy(self, policy_id: int, test_event: dict) -> dict:
        return self._sword.test_policy(policy_id, test_event)

    async def sword_reload_policies(self) -> None:
        """Reload Sword policies from DB."""
        if self._db_session_factory:
            await self._sword.load_policies(self._db_session_factory)

    # Overwatch Protocol public API
    def get_overwatch_status(self) -> dict:
        return self._overwatch.get_status()

    def get_overwatch_integrity(self) -> dict:
        return self._overwatch.check_integrity()

    async def evaluate_alert(self, event: dict) -> list[dict]:
        """Called by AlertManager — Bond evaluates every alert for Sword response."""
        if not self._sword._enabled:
            return []
        return await self._sword.evaluate_event(
            event,
            remediation_engine=self._remediation_engine,
            db_factory=self._db_session_factory,
        )

    def get_status(self) -> dict:
        """Return Bond's operational status for the frontend."""
        latest = self.get_latest_report()  # already filtered
        # Use adaptive interval if brain has computed one
        effective_interval = self._brain._adaptive_interval if self._brain.generation > 0 else self._scan_interval
        # Compute next scan time
        next_scan = None
        if self._last_scan and self.running:
            next_scan = (self._last_scan + timedelta(seconds=effective_interval)).isoformat()

        state = "offline"
        if self.running:
            state = "scanning" if self._scanning else "idle"

        return {
            "state": state,
            "last_scan": self._last_scan.isoformat() if self._last_scan else None,
            "next_scan": next_scan,
            "threat_count": latest["threat_count"] if latest else 0,
            "scan_interval_seconds": effective_interval,
            "total_scans": self._total_scans,
            "total_threats_found": self._total_threats_found,
            "reports_buffered": len(self._reports),
            "neutralized_count": len(self._neutralized_ids),
            "intelligence": self._brain.get_intelligence(),
            "sword": self._sword.get_stats(),
            "overwatch": self._overwatch.get_status(),
        }

    # ------------------------------------------------------------------
    # Scan loop
    # ------------------------------------------------------------------

    async def _scan_loop(self) -> None:
        """Run scans using adaptive interval from IntelligenceBrain."""
        while self.running:
            try:
                # Use adaptive interval if brain has enough data, else configured default
                interval = self._brain._adaptive_interval if self._brain.generation > 0 else self._scan_interval
                await asyncio.sleep(interval)
                if self.running:
                    await self._execute_scan()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.error("commander_bond_scan_loop_error", error=str(exc))
                interval = self._brain._adaptive_interval if self._brain.generation > 0 else self._scan_interval
                await asyncio.sleep(interval)

    async def _execute_scan(self) -> None:
        """Orchestrate a full intelligence sweep across all sources."""
        self._scanning = True
        scan_start = time.monotonic()
        self.logger.info("commander_bond_scan_begin", status="Bond is in the field...")

        findings: list[dict] = []

        # Run all source checks concurrently
        results = await asyncio.gather(
            self._check_cisa_kev(),
            self._check_nvd_cves(),
            self._check_urlhaus(),
            self._check_feodo_c2(),
            self._check_threatfox(),
            self._check_malware_bazaar(),
            return_exceptions=True,
        )

        source_names = [
            "CISA KEV", "NVD", "URLhaus",
            "Feodo Tracker", "ThreatFox", "MalwareBazaar",
        ]
        for name, result in zip(source_names, results):
            if isinstance(result, Exception):
                self.logger.error(
                    "commander_bond_source_error", source=name, error=str(result),
                )
            elif isinstance(result, list):
                findings.extend(result)
                # Phase 14: Record per-source findings for brain quality scoring
                self._brain.record_findings(name, result)

        scan_duration = round(time.monotonic() - scan_start, 2)
        report = self._generate_report(findings, scan_duration)

        self._reports.append(report)
        self._total_scans += 1
        self._total_threats_found += report["threat_count"]
        self._last_scan = datetime.now(timezone.utc)
        self.heartbeat()

        # Phase 14: Update threat velocity and adaptive interval
        self._brain.update_threat_velocity(report["threat_count"])

        # Create alerts for critical threats (skip duplicates already in DB)
        if self._alert_manager and self._db_session_factory:
            # Collect existing Bond alert titles to avoid duplicates on restart
            existing_titles: set[str] = set()
            try:
                from ..models.alert import Alert as AlertModel
                from sqlalchemy import select
                async with self._db_session_factory() as session:
                    result = await session.execute(
                        select(AlertModel.title).where(
                            AlertModel.module_source == "commander_bond",
                        )
                    )
                    existing_titles = {row[0] for row in result.fetchall()}
            except Exception as exc:
                self.logger.debug("commander_bond_dedup_query_failed", error=str(exc))

            new_alert_count = 0
            for threat in report["threats"]:
                if threat["severity"] == "critical":
                    title = f"BOND INTELLIGENCE: {threat['name']}"
                    if title in existing_titles:
                        continue  # Already in DB — skip
                    try:
                        await self._alert_manager.create_alert(
                            severity="critical",
                            module_source="commander_bond",
                            title=title,
                            description=threat["bond_assessment"][:500],
                            details=threat,
                        )
                        new_alert_count += 1
                    except Exception as exc:
                        self.logger.error(
                            "commander_bond_alert_error", error=str(exc),
                        )
            if new_alert_count > 0:
                self.logger.info("commander_bond_new_alerts", count=new_alert_count)

        self._scanning = False
        level = "all_clear" if report["all_clear"] else f"{report['threat_count']} threats"
        self.logger.info(
            "commander_bond_scan_complete",
            status="Shaken, not stirred -- analysis complete",
            threats=report["threat_count"],
            duration=scan_duration,
            level=level,
        )

    # ------------------------------------------------------------------
    # Source: CISA KEV
    # ------------------------------------------------------------------

    async def _check_cisa_kev(self) -> list[dict]:
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        findings: list[dict] = []
        try:
            data = await self._fetch_json("GET", CISA_KEV_URL)
            if not data:
                return findings

            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities[-self._cisa_limit:]:
                cve_id = vuln.get("cveID", "")
                if not cve_id or cve_id in self._known_cve_ids:
                    continue

                self._known_cve_ids.add(cve_id)
                findings.append({
                    "id": cve_id,
                    "name": f"{cve_id}: {vuln.get('vulnerabilityName', 'Unknown')}",
                    "category": "known_exploited_vulnerability",
                    "severity": "critical",
                    "source": "CISA KEV",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "kev",
                        "cve": cve_id,
                        "name": vuln.get("vulnerabilityName", ""),
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "action": vuln.get("requiredAction", ""),
                        "due_date": vuln.get("dueDate", ""),
                    }),
                    "iocs": [cve_id],
                    "mitre_techniques": ["T1190"],  # Exploit Public-Facing Application
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "cve",
                        "cve": cve_id,
                        "name": vuln.get("vulnerabilityName", ""),
                        "vendor": vuln.get("vendorProject", ""),
                    }),
                    "raw": {
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "date_added": vuln.get("dateAdded", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "required_action": vuln.get("requiredAction", ""),
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_cisa_kev_error", error=str(exc))
        return findings

    # ------------------------------------------------------------------
    # Source: NVD CVEs
    # ------------------------------------------------------------------

    async def _check_nvd_cves(self) -> list[dict]:
        """Fetch recent CVEs from NVD, filtered to CVSS >= 7.0 and Windows-relevant."""
        findings: list[dict] = []
        try:
            nvd_url = f"{NVD_CVE_BASE_URL}?resultsPerPage={self._nvd_limit}"
            data = await self._fetch_json("GET", nvd_url)
            if not data:
                return findings

            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id or cve_id in self._known_cve_ids:
                    continue

                # Extract CVSS score
                cvss_score = self._extract_cvss_score(cve_data)
                if cvss_score < 7.0:
                    continue

                # Check Windows relevance from descriptions or configurations
                description = self._extract_cve_description(cve_data)
                if not self._is_windows_relevant(description, cve_data):
                    continue

                self._known_cve_ids.add(cve_id)
                severity = "critical" if cvss_score >= 9.0 else "high"

                findings.append({
                    "id": cve_id,
                    "name": f"{cve_id} (CVSS {cvss_score})",
                    "category": "cve",
                    "severity": severity,
                    "source": "NVD",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "cve",
                        "cve": cve_id,
                        "cvss": cvss_score,
                        "description": description[:200],
                    }),
                    "iocs": [cve_id],
                    "mitre_techniques": ["T1203"],  # Exploitation for Client Execution
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "cve",
                        "cve": cve_id,
                        "name": description[:120],
                        "vendor": "multiple",
                    }),
                    "raw": {
                        "cvss_score": cvss_score,
                        "description": description[:500],
                        "published": cve_data.get("published", ""),
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_nvd_error", error=str(exc))
        return findings

    @staticmethod
    def _extract_cvss_score(cve_data: dict) -> float:
        """Extract the highest CVSS score from a CVE record."""
        metrics = cve_data.get("metrics", {})
        best = 0.0
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            for m in metric_list:
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore", 0.0)
                if score > best:
                    best = score
        return best

    @staticmethod
    def _extract_cve_description(cve_data: dict) -> str:
        """Extract English description from a CVE record."""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""

    @staticmethod
    def _is_windows_relevant(description: str, cve_data: dict) -> bool:
        """Heuristic check for Windows relevance."""
        windows_keywords = {
            "windows", "microsoft", "win32", "active directory", "ntlm",
            "smb", "rdp", "exchange", "iis", ".net", "powershell",
            "office", "outlook", "defender", "kernel32", "ntdll",
        }
        text = description.lower()
        for keyword in windows_keywords:
            if keyword in text:
                return True

        # Also check configurations / affected products
        configs = cve_data.get("configurations", [])
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "").lower()
                    if "microsoft" in criteria or "windows" in criteria:
                        return True
        return False

    # ------------------------------------------------------------------
    # Source: URLhaus
    # ------------------------------------------------------------------

    async def _check_urlhaus(self) -> list[dict]:
        """Fetch recent malware distribution URLs from URLhaus."""
        findings: list[dict] = []
        try:
            data = await self._fetch_json("POST", URLHAUS_RECENT_URL)
            if not data:
                return findings

            urls = data.get("urls", [])
            for entry in urls[:self._urlhaus_limit]:
                url = entry.get("url", "")
                url_hash = hashlib.sha256(url.encode()).hexdigest()
                if url_hash in self._known_ioc_hashes:
                    continue

                self._known_ioc_hashes.add(url_hash)
                threat_type = entry.get("threat", "malware_download")
                tags = entry.get("tags") or []

                findings.append({
                    "id": f"URLHAUS-{entry.get('id', url_hash[:8])}",
                    "name": f"Malware URL: {url[:80]}",
                    "category": "malware_url",
                    "severity": "high",
                    "source": "URLhaus",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "malware_url",
                        "url": url,
                        "threat": threat_type,
                        "tags": tags,
                    }),
                    "iocs": [url],
                    "mitre_techniques": ["T1566.002"],  # Phishing: Spear-phishing Link
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "malware",
                        "url": url,
                        "threat": threat_type,
                    }),
                    "raw": {
                        "url": url,
                        "url_status": entry.get("url_status", ""),
                        "threat": threat_type,
                        "tags": tags,
                        "date_added": entry.get("dateadded", ""),
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_urlhaus_error", error=str(exc))
        return findings

    # ------------------------------------------------------------------
    # Source: Feodo Tracker
    # ------------------------------------------------------------------

    async def _check_feodo_c2(self) -> list[dict]:
        """Fetch recommended C2 IP blocklist from Feodo Tracker."""
        findings: list[dict] = []
        try:
            data = await self._fetch_json("GET", FEODO_BLOCKLIST_URL)
            if not data:
                return findings

            entries = data if isinstance(data, list) else data.get("data", data.get("entries", []))
            if not isinstance(entries, list):
                return findings

            for entry in entries[:self._feodo_limit]:
                if isinstance(entry, dict):
                    ip = entry.get("ip_address", entry.get("dst_ip", ""))
                    port = entry.get("dst_port", entry.get("port", ""))
                    malware = entry.get("malware", "unknown")
                    status = entry.get("status", "")
                else:
                    ip = str(entry)
                    port = ""
                    malware = "unknown"
                    status = ""

                if not ip:
                    continue

                ip_hash = hashlib.sha256(ip.encode()).hexdigest()
                if ip_hash in self._known_ioc_hashes:
                    continue

                self._known_ioc_hashes.add(ip_hash)
                findings.append({
                    "id": f"FEODO-{ip_hash[:12]}",
                    "name": f"Botnet C2: {ip}:{port} ({malware})",
                    "category": "c2_infrastructure",
                    "severity": "critical",
                    "source": "Feodo Tracker",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "c2",
                        "ip": ip,
                        "port": port,
                        "malware": malware,
                    }),
                    "iocs": [ip],
                    "mitre_techniques": ["T1071.001"],  # Application Layer Protocol
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "c2",
                        "ip": ip,
                        "port": port,
                        "malware": malware,
                    }),
                    "raw": {
                        "ip": ip,
                        "port": port,
                        "malware": malware,
                        "status": status,
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_feodo_error", error=str(exc))
        return findings

    # ------------------------------------------------------------------
    # Source: ThreatFox
    # ------------------------------------------------------------------

    async def _check_threatfox(self) -> list[dict]:
        """Fetch recent IOCs from ThreatFox."""
        findings: list[dict] = []
        try:
            payload = {"query": "get_iocs", "days": 1}
            data = await self._fetch_json("POST", THREATFOX_API_URL, json_body=payload)
            if not data or data.get("query_status") != "ok":
                return findings

            iocs = data.get("data", [])
            if not isinstance(iocs, list):
                return findings

            for entry in iocs[:self._threatfox_limit]:
                ioc_value = entry.get("ioc", "")
                ioc_hash = hashlib.sha256(ioc_value.encode()).hexdigest()
                if ioc_hash in self._known_ioc_hashes:
                    continue

                self._known_ioc_hashes.add(ioc_hash)
                malware = entry.get("malware_printable", "unknown")
                ioc_type = entry.get("ioc_type", "unknown")
                threat_type = entry.get("threat_type", "unknown")
                confidence = entry.get("confidence_level", 0)

                severity = "critical" if confidence >= 75 else "high" if confidence >= 50 else "medium"

                findings.append({
                    "id": f"TFOX-{entry.get('id', ioc_hash[:8])}",
                    "name": f"ThreatFox IOC: {malware} ({ioc_type})",
                    "category": "ioc",
                    "severity": severity,
                    "source": "ThreatFox",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "ioc",
                        "ioc_value": ioc_value,
                        "malware": malware,
                        "ioc_type": ioc_type,
                        "confidence": confidence,
                    }),
                    "iocs": [ioc_value],
                    "mitre_techniques": entry.get("mitre_attack", ["T1059"]),
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "malware",
                        "malware": malware,
                        "ioc_type": ioc_type,
                        "threat": threat_type,
                    }),
                    "raw": {
                        "ioc": ioc_value,
                        "ioc_type": ioc_type,
                        "threat_type": threat_type,
                        "malware": malware,
                        "confidence": confidence,
                        "tags": entry.get("tags"),
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_threatfox_error", error=str(exc))
        return findings

    # ------------------------------------------------------------------
    # Source: MalwareBazaar
    # ------------------------------------------------------------------

    async def _check_malware_bazaar(self) -> list[dict]:
        """Fetch recent malware samples from MalwareBazaar."""
        findings: list[dict] = []
        try:
            payload = {"query": "get_recent", "selector": "time"}
            data = await self._fetch_json("POST", MALWAREBAZAAR_API_URL, json_body=payload)
            if not data or data.get("query_status") != "ok":
                return findings

            samples = data.get("data", [])
            if not isinstance(samples, list):
                return findings

            for sample in samples[:15]:
                sha256 = sample.get("sha256_hash", "")
                if not sha256 or sha256 in self._known_ioc_hashes:
                    continue

                self._known_ioc_hashes.add(sha256)
                file_name = sample.get("file_name", "unknown")
                file_type = sample.get("file_type", "unknown")
                signature = sample.get("signature") or "unsigned"
                tags = sample.get("tags") or []

                # Determine severity from tags / signature
                severity = "high"
                ransomware_indicators = {"ransomware", "ransom", "locker", "crypt"}
                if any(t.lower() in ransomware_indicators for t in tags):
                    severity = "critical"
                if signature and any(k in signature.lower() for k in ransomware_indicators):
                    severity = "critical"

                findings.append({
                    "id": f"MBAZ-{sha256[:12]}",
                    "name": f"Malware sample: {file_name} ({file_type})",
                    "category": "malware_sample",
                    "severity": severity,
                    "source": "MalwareBazaar",
                    "bond_assessment": self._bond_assessment_text({
                        "type": "malware_sample",
                        "file_name": file_name,
                        "file_type": file_type,
                        "signature": signature,
                        "sha256": sha256,
                    }),
                    "iocs": [sha256],
                    "mitre_techniques": ["T1204.002"],  # User Execution: Malicious File
                    "cereberus_prompt": self._generate_cereberus_prompt({
                        "type": "ransomware" if severity == "critical" else "malware",
                        "file_name": file_name,
                        "sha256": sha256,
                        "signature": signature,
                    }),
                    "raw": {
                        "sha256": sha256,
                        "md5": sample.get("md5_hash", ""),
                        "file_name": file_name,
                        "file_type": file_type,
                        "file_size": sample.get("file_size", 0),
                        "signature": signature,
                        "tags": tags,
                        "first_seen": sample.get("first_seen", ""),
                    },
                })
        except Exception as exc:
            self.logger.error("commander_bond_malwarebazaar_error", error=str(exc))
        return findings

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    async def _fetch_json(
        self,
        method: str,
        url: str,
        json_body: dict | None = None,
    ) -> dict | list | None:
        """Fetch JSON from a URL with timeout and error handling."""
        if not self._http_session or self._http_session.closed:
            self.logger.warning("commander_bond_no_session")
            return None

        try:
            if method.upper() == "POST":
                async with self._http_session.post(url, json=json_body) as resp:
                    if resp.status != 200:
                        self.logger.warning(
                            "commander_bond_http_error",
                            url=url, status=resp.status,
                        )
                        return None
                    return await resp.json(content_type=None)
            else:
                async with self._http_session.get(url) as resp:
                    if resp.status != 200:
                        self.logger.warning(
                            "commander_bond_http_error",
                            url=url, status=resp.status,
                        )
                        return None
                    return await resp.json(content_type=None)
        except asyncio.TimeoutError:
            self.logger.warning("commander_bond_timeout", url=url)
            return None
        except Exception as exc:
            self.logger.warning("commander_bond_fetch_error", url=url, error=str(exc))
            return None

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def _generate_report(self, findings: list[dict], scan_duration: float) -> dict:
        """Compile findings into a Bond intelligence briefing."""
        now = datetime.now(timezone.utc)
        self._report_sequence += 1
        report_id = f"BOND-{now.strftime('%Y-%m-%d')}-{self._report_sequence:03d}"

        all_clear = len(findings) == 0

        if all_clear:
            summary = "The name is Bond. All clear on the perimeter."
        elif len(findings) == 1:
            summary = (
                f"Bond identified 1 threat during the sweep. "
                f"Recommend immediate review of the dossier."
            )
        else:
            critical_count = sum(1 for f in findings if f.get("severity") == "critical")
            if critical_count > 0:
                summary = (
                    f"Bond identified {len(findings)} threats, {critical_count} critical. "
                    f"License to kill has been granted -- act immediately."
                )
            else:
                summary = (
                    f"Bond identified {len(findings)} threats during the sweep. "
                    f"All targets are under surveillance."
                )

        return {
            "id": report_id,
            "timestamp": now.isoformat(),
            "scan_duration_seconds": scan_duration,
            "status": "INTELLIGENCE GATHERED" if not all_clear else "ALL CLEAR",
            "threat_count": len(findings),
            "threats": findings,
            "summary": summary,
            "all_clear": all_clear,
        }

    # ------------------------------------------------------------------
    # Bond personality
    # ------------------------------------------------------------------

    @staticmethod
    def _bond_assessment_text(threat: dict) -> str:
        """Generate a Bond-style assessment for a threat."""
        threat_type = threat.get("type", "unknown")

        if threat_type == "kev":
            return (
                f"THREAT DOSSIER: {threat.get('cve', 'Unknown CVE')} -- "
                f"{threat.get('name', 'classified vulnerability')}. "
                f"Vendor: {threat.get('vendor', 'unknown')}, "
                f"Product: {threat.get('product', 'unknown')}. "
                f"This exploit is confirmed active in the wild. "
                f"Required action: {threat.get('action', 'patch immediately')}. "
                f"Deadline: {threat.get('due_date', 'yesterday')}. "
                f"License to kill -- immediate action required."
            )

        if threat_type == "cve":
            cvss = threat.get("cvss", "N/A")
            return (
                f"THREAT DOSSIER: {threat.get('cve', 'Unknown CVE')} "
                f"with CVSS {cvss}. "
                f"{threat.get('description', 'Details classified.')} "
                f"{'License to kill -- immediate action required.' if isinstance(cvss, (int, float)) and cvss >= 9.0 else 'Marked for elimination.'}"
            )

        if threat_type == "malware_url":
            return (
                f"THREAT DOSSIER: Malware distribution point identified at "
                f"{threat.get('url', 'classified location')}. "
                f"Threat classification: {threat.get('threat', 'unknown')}. "
                f"Tags: {', '.join(threat.get('tags', [])[:5]) or 'none'}. "
                f"Marked for elimination."
            )

        if threat_type == "c2":
            return (
                f"THREAT DOSSIER: Command & control server detected. "
                f"Target: {threat.get('ip', 'unknown')}:{threat.get('port', '?')}. "
                f"Associated malware family: {threat.get('malware', 'unknown')}. "
                f"This is an active enemy communication channel. "
                f"License to kill -- immediate action required."
            )

        if threat_type == "ioc":
            return (
                f"THREAT DOSSIER: Indicator of compromise intercepted. "
                f"Type: {threat.get('ioc_type', 'unknown')}. "
                f"Malware: {threat.get('malware', 'unknown')}. "
                f"Confidence: {threat.get('confidence', 0)}%. "
                f"{'License to kill -- immediate action required.' if threat.get('confidence', 0) >= 75 else 'Under surveillance.'}"
            )

        if threat_type == "malware_sample":
            return (
                f"THREAT DOSSIER: Malware sample acquired. "
                f"Filename: {threat.get('file_name', 'unknown')}. "
                f"Type: {threat.get('file_type', 'unknown')}. "
                f"Signature: {threat.get('signature', 'unsigned')}. "
                f"SHA256: {threat.get('sha256', 'unknown')[:16]}... "
                f"Marked for elimination."
            )

        return (
            f"THREAT DOSSIER: Unclassified threat detected. "
            f"Details: {str(threat)[:200]}. Under surveillance."
        )

    # ------------------------------------------------------------------
    # Cereberus remediation prompts
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_cereberus_prompt(threat: dict) -> str:
        """Generate a Cereberus-specific remediation prompt for a threat."""
        threat_type = threat.get("type", "unknown")

        if threat_type == "cve":
            return (
                f"Vulnerability {threat.get('cve', 'unknown')} "
                f"({threat.get('name', 'unnamed')}) reported by "
                f"{threat.get('vendor', 'unknown')}. "
                f"Recommended Cereberus actions: "
                f"1) Update vuln_scanner signatures to detect this CVE. "
                f"2) Add {threat.get('cve', '')} to IOC database. "
                f"3) Scan all monitored hosts for affected software versions."
            )

        if threat_type == "malware":
            return (
                f"Malware activity detected -- {threat.get('malware', threat.get('threat', 'unknown'))}. "
                f"Recommended Cereberus actions: "
                f"1) Add IOC indicators to rule_engine detection rules. "
                f"2) Update IOC feed with new malware hashes/URLs. "
                f"3) Scan file_integrity monitored paths for matching artifacts. "
                f"4) Alert process_analyzer to flag processes loading related modules."
            )

        if threat_type == "c2":
            return (
                f"C2 server identified: {threat.get('ip', 'unknown')}:{threat.get('port', '?')} "
                f"(malware family: {threat.get('malware', 'unknown')}). "
                f"Recommended Cereberus actions: "
                f"1) Add IP to firewall block list via remediation engine (block_ip action). "
                f"2) Update IOC database with C2 IP and associated indicators. "
                f"3) Scan network_sentinel connection logs for any past contact. "
                f"4) Check brute_force_shield logs for related activity."
            )

        if threat_type == "ransomware":
            return (
                f"Ransomware sample detected -- {threat.get('signature', threat.get('file_name', 'unknown'))}. "
                f"SHA256: {threat.get('sha256', 'unknown')}. "
                f"Recommended Cereberus actions: "
                f"1) Update ransomware_detector pattern database with sample hash. "
                f"2) Add file hash to IOC feed for real-time matching. "
                f"3) Verify file_integrity baselines for critical system directories. "
                f"4) Prepare incident response playbook for ransomware containment."
            )

        return (
            f"Threat detected: {str(threat)[:200]}. "
            f"Recommended Cereberus actions: "
            f"1) Review and update detection rules. "
            f"2) Add relevant IOCs to the database."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _filter_report(self, report: dict) -> dict:
        """Return a copy of the report with neutralized threats removed."""
        if not self._neutralized_ids:
            return report
        active_threats = [
            t for t in report.get("threats", [])
            if t.get("id") not in self._neutralized_ids
        ]
        return {
            **report,
            "threats": active_threats,
            "threat_count": len(active_threats),
            "all_clear": len(active_threats) == 0,
        }

    def get_reports(self) -> list[dict]:
        """Return all buffered intelligence reports, newest first."""
        reports = [self._filter_report(r) for r in self._reports]
        reports.reverse()
        return reports

    def get_latest_report(self) -> Optional[dict]:
        """Return the most recent intelligence report, or None."""
        if not self._reports:
            return None
        return self._filter_report(self._reports[-1])

    def get_all_threats(
        self,
        category: str | None = None,
        severity: str | None = None,
    ) -> list[dict]:
        """Return all threats across all reports, optionally filtered.

        Args:
            category: Filter by threat category (e.g. 'c2_infrastructure', 'cve').
            severity: Filter by severity level ('critical', 'high', 'medium', 'low').

        Returns:
            List of threat dicts, newest first.
        """
        threats: list[dict] = []
        for report in reversed(self._reports):
            for threat in report.get("threats", []):
                if threat.get("id") in self._neutralized_ids:
                    continue
                if category and threat.get("category") != category:
                    continue
                if severity and threat.get("severity") != severity:
                    continue
                threats.append(threat)
        return threats

    def neutralize_threat(self, threat_id: str) -> bool:
        """Mark a threat as neutralized — removes it from all responses.

        Returns True if the threat was found and neutralized, False if not found.
        """
        # Verify the threat exists in at least one report
        for report in self._reports:
            for threat in report.get("threats", []):
                if threat.get("id") == threat_id:
                    self._neutralized_ids.add(threat_id)
                    self.logger.info(
                        "commander_bond_threat_neutralized",
                        threat_id=threat_id,
                        status="Target eliminated.",
                    )
                    return True
        return False

    def neutralize_all(self) -> int:
        """Mark all current threats as neutralized. Returns count neutralized."""
        count = 0
        for report in self._reports:
            for threat in report.get("threats", []):
                tid = threat.get("id")
                if tid and tid not in self._neutralized_ids:
                    self._neutralized_ids.add(tid)
                    count += 1
        if count:
            self.logger.info(
                "commander_bond_all_neutralized",
                count=count,
                status="All targets eliminated.",
            )
        return count

    # ------------------------------------------------------------------
    # Phase 14 Track 2: Intelligence API
    # ------------------------------------------------------------------

    def get_intelligence(self) -> dict:
        """Return intelligence brain metrics."""
        return self._brain.get_intelligence()

    def mark_threat_irrelevant(self, threat_id: str) -> bool:
        """Mark a threat as irrelevant — feeds back into source quality scoring."""
        for report in self._reports:
            for threat in report.get("threats", []):
                if threat.get("id") == threat_id:
                    source = threat.get("source", "")
                    self._brain.mark_irrelevant(threat_id, source)
                    self._neutralized_ids.add(threat_id)
                    self.logger.info(
                        "commander_bond_threat_irrelevant",
                        threat_id=threat_id, source=source,
                        status="Feedback recorded. Source quality adjusted.",
                    )
                    return True
        return False

    def get_correlated_iocs(self) -> list[dict]:
        """Return IOCs seen across multiple feeds."""
        return self._brain.get_correlated_iocs()

    # ------------------------------------------------------------------
    # Phase 15: Sword Protocol event handler + Overwatch loop
    # ------------------------------------------------------------------

    async def _sword_evaluate(self, event_type: str, event: dict) -> None:
        """EventBus callback — evaluate every event for Sword response."""
        try:
            actions = await self._sword.evaluate_event(
                event,
                remediation_engine=self._remediation_engine,
                db_factory=self._db_session_factory,
            )
            for action in actions:
                if action.get("result") == "success" and self._alert_manager:
                    await self._alert_manager.create_alert(
                        severity="high",
                        module_source="sword_protocol",
                        title=f"Sword Protocol: {action.get('codename', 'UNKNOWN')} executed",
                        description=f"Autonomous response executed. Result: {action.get('result')}. "
                                    f"Escalation level: {action.get('escalation_level', 0)}.",
                        details=action,
                    )
        except Exception as e:
            self.logger.error("sword_evaluate_failed", error=str(e))

    async def _overwatch_loop(self) -> None:
        """Periodic integrity check loop."""
        await asyncio.sleep(self._overwatch._check_interval)
        while self.running:
            try:
                report = self._overwatch.check_integrity()
                if report.get("status") == "tampered" and self._alert_manager:
                    await self._alert_manager.create_alert(
                        severity="critical",
                        module_source="overwatch_protocol",
                        title="OVERWATCH: Code tampering detected",
                        description=f"Modified files: {', '.join(report.get('tampered', [])[:5])}. "
                                    f"Missing files: {', '.join(report.get('missing', [])[:5])}.",
                        details=report,
                    )
                await asyncio.sleep(self._overwatch._check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("overwatch_loop_error", error=str(e))
                await asyncio.sleep(self._overwatch._check_interval)

    # ------------------------------------------------------------------
    # Phase 14 Track 3: Guardian Protocol — Bond watches over Smith
    # ------------------------------------------------------------------

    def get_guardian_status(self) -> dict:
        """Return Guardian oversight status."""
        return {
            "containment_level": self._containment_level,
            "level_name": self._containment_names.get(self._containment_level, "UNKNOWN"),
            "lockdown_active": self._containment_level >= 3,
            "lockdown_reason": self._agent_smith._guardian_lockdown_reason if self._agent_smith and self._agent_smith._guardian_lockdown else "",
            "lockdown_at": self._lockdown_at,
            "stability_score": round(self._stability_score, 1),
            "interventions": list(self._guardian_interventions),
            "last_check": self._last_guardian_check,
        }

    async def guardian_clear(self) -> dict:
        """Clear guardian lockdown — re-enable Smith."""
        if self._agent_smith is None:
            return {"status": "error", "message": "Smith not attached"}

        self._agent_smith._guardian_clear()
        prev_level = self._containment_level
        self._containment_level = 0
        self._stability_score = 100.0
        self._lockdown_at = None
        self._smith_prev_stats = None

        self._guardian_interventions.appendleft({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": "GREEN",
            "reason": "Manual clear by operator",
            "stability_score": 100.0,
            "action_taken": f"Containment lowered from {self._containment_names.get(prev_level, '?')} to GREEN",
        })

        self.logger.info("guardian_lockdown_cleared", previous_level=prev_level)
        return {
            "status": "cleared",
            "previous_level": self._containment_names.get(prev_level, "?"),
            "message": "Guardian lockdown cleared. Smith is free to operate.",
        }

    async def _guardian_loop(self) -> None:
        """Monitor Agent Smith every 10 seconds when active."""
        await asyncio.sleep(5)  # Initial delay
        while self.running:
            try:
                await asyncio.sleep(10)
                if not self.running or self._agent_smith is None:
                    continue
                await self._guardian_check()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.error("guardian_loop_error", error=str(exc))
                await asyncio.sleep(10)

    async def _guardian_check(self) -> None:
        """Evaluate Smith's stability and escalate containment if needed."""
        smith = self._agent_smith
        if smith is None:
            return

        now = datetime.now(timezone.utc)
        self._last_guardian_check = now.isoformat()

        # Collect Smith stats
        stats = {
            "active": smith._active,
            "events_injected": smith._events_injected,
            "attack_log_size": len(smith._attack_log),
            "sessions_completed": len(smith._results),
            "lockdown": smith._guardian_lockdown,
        }

        # Compute detection rate from recent attacks
        recent_attacks = list(smith._attack_log)[:20]
        total = len(recent_attacks)
        detected = sum(1 for a in recent_attacks if a.get("detection", {}).get("detected", False))
        detection_rate = detected / total if total > 0 else 1.0

        # -- Instability checks --
        problems: list[str] = []
        severity = 0  # 0=fine, 1=yellow, 2=orange, 3=red

        # 1) Detection rate collapse (below 10% with enough data)
        if total >= 5 and detection_rate < 0.10:
            problems.append(f"Detection rate collapsed: {detection_rate:.0%} ({detected}/{total})")
            severity = max(severity, 2)

        # 2) Runaway event injection (more than 2 events/sec)
        if self._smith_prev_stats and smith._active:
            prev_events = self._smith_prev_stats.get("events_injected", 0)
            delta_events = stats["events_injected"] - prev_events
            if delta_events > 20:  # 20 events in 10 seconds = 2/sec
                problems.append(f"Runaway injection: {delta_events} events in 10s")
                severity = max(severity, 3)

        # 3) Too many sessions too quickly
        if self._smith_prev_stats:
            prev_sessions = self._smith_prev_stats.get("sessions_completed", 0)
            if stats["sessions_completed"] - prev_sessions >= 3:
                problems.append(f"Session frequency abuse: {stats['sessions_completed'] - prev_sessions} sessions in 10s")
                severity = max(severity, 2)

        # 4) Consecutive missed attacks (10+)
        if total >= 10:
            consecutive_missed = 0
            for a in recent_attacks:
                if not a.get("detection", {}).get("detected", False):
                    consecutive_missed += 1
                else:
                    break
            if consecutive_missed >= 10:
                problems.append(f"Consecutive missed attacks: {consecutive_missed}")
                severity = max(severity, 2)

        # Save for next delta check
        self._smith_prev_stats = stats

        # -- Stability score update --
        if not problems:
            # Recover stability slowly
            self._stability_score = min(100.0, self._stability_score + 2.0)
        else:
            # Degrade based on severity
            penalty = {1: 5.0, 2: 15.0, 3: 30.0}.get(severity, 0.0)
            self._stability_score = max(0.0, self._stability_score - penalty)

        # -- Containment level update --
        new_level = self._containment_level
        if self._stability_score >= 80:
            new_level = 0
        elif self._stability_score >= 50:
            new_level = 1
        elif self._stability_score >= 20:
            new_level = 2
        else:
            new_level = 3

        # Never go down automatically — only manual clear lowers level
        new_level = max(new_level, self._containment_level) if severity > 0 else new_level

        # -- Take action on escalation --
        if new_level > self._containment_level:
            old_name = self._containment_names.get(self._containment_level, "?")
            new_name = self._containment_names.get(new_level, "?")
            action = ""

            if new_level >= 3:
                # RED — force lockdown
                if smith._active:
                    await smith._emergency_disengage(f"Guardian RED: {'; '.join(problems)}")
                    action = "Emergency disengage + lockdown"
                else:
                    smith._guardian_lockdown = True
                    smith._guardian_lockdown_reason = f"Guardian RED: {'; '.join(problems)}"
                    action = "Lockdown engaged"
                self._lockdown_at = now.isoformat()
            elif new_level >= 2:
                # ORANGE — cap intensity
                action = "Intensity cap advisory (level 1 max)"
            else:
                action = "Warning logged"

            intervention = {
                "timestamp": now.isoformat(),
                "level": new_name,
                "reason": "; ".join(problems),
                "stability_score": round(self._stability_score, 1),
                "action_taken": f"Escalated {old_name} -> {new_name}: {action}",
            }
            self._guardian_interventions.appendleft(intervention)
            self._containment_level = new_level

            self.logger.warning(
                "guardian_escalation",
                from_level=old_name, to_level=new_name,
                stability=round(self._stability_score, 1),
                problems=problems,
                action=action,
            )

# ---------------------------------------------------------------------------
# Phase 15 Track 4: Sword Protocol — Bond's autonomous response engine
# ---------------------------------------------------------------------------

class SwordProtocol:
    """Bond's autonomous response engine.

    Evaluates security events against response policies and executes
    remediation actions with escalation chains. Bond decides. Bond strikes.
    """

    def __init__(self) -> None:
        self._policies: list[dict] = []
        self._execution_log: deque = deque(maxlen=500)
        self._rate_limiter: dict[int, deque] = {}  # policy_id -> timestamps
        self._enabled: bool = True
        self._global_lockout: bool = False
        self._stats: dict = {
            "total_evaluations": 0,
            "total_strikes": 0,
            "total_rate_limited": 0,
            "total_failed": 0,
            "last_strike": None,
        }
        self._logger = get_logger("sword_protocol")

    def enable(self) -> None:
        """Draw the sword — enable autonomous response."""
        self._enabled = True
        self._global_lockout = False
        self._logger.info("sword_drawn", status="The sword is drawn.")

    def disable(self) -> None:
        """Sheathe the sword — disable autonomous response."""
        self._enabled = False
        self._logger.info("sword_sheathed", status="The sword is sheathed.")

    def lockout(self) -> None:
        """Emergency lockout — no autonomous actions until cleared."""
        self._global_lockout = True
        self._enabled = False
        self._logger.warning("sword_lockout", status="Emergency lockout engaged.")

    def clear_lockout(self) -> None:
        """Clear lockout — restore autonomous capability."""
        self._global_lockout = False
        self._enabled = True
        self._logger.info("sword_lockout_cleared", status="Lockout cleared.")

    def get_stats(self) -> dict:
        """Return Sword Protocol statistics."""
        return {
            **self._stats,
            "enabled": self._enabled,
            "lockout": self._global_lockout,
            "policies_loaded": len(self._policies),
            "recent_executions": list(self._execution_log)[:20],
        }

    def matches_condition(self, policy: dict, event: dict) -> bool:
        """Check if an event triggers a policy's conditions."""
        conditions = policy.get("trigger_conditions", {})
        trigger_type = policy.get("trigger_type", "")

        if not conditions:
            return False

        # Match by trigger type
        event_source = event.get("module_source", event.get("source_module", ""))
        event_severity = event.get("severity", "")
        event_type = event.get("event_type", "")
        event_rule_id = event.get("rule_id", "")
        event_finding_type = event.get("finding_type", "")

        if trigger_type == "module_event":
            source_match = conditions.get("source_module", "")
            if source_match and source_match not in event_source:
                return False
            event_match = conditions.get("event_type", "")
            if event_match and event_match not in event_type:
                return False
            return True

        if trigger_type == "severity":
            required = conditions.get("min_severity", "critical")
            severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            return severity_order.get(event_severity, 0) >= severity_order.get(required, 4)

        if trigger_type == "rule_match":
            pattern = conditions.get("rule_pattern", "")
            if pattern and pattern in event_rule_id:
                sev_min = conditions.get("min_severity", "")
                if sev_min:
                    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                    return severity_order.get(event_severity, 0) >= severity_order.get(sev_min, 0)
                return True
            return False

        if trigger_type == "yara_match":
            if event_type != "yara_match":
                return False
            sev_min = conditions.get("min_severity", "high")
            severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            return severity_order.get(event_severity, 0) >= severity_order.get(sev_min, 3)

        if trigger_type == "memory_anomaly":
            if event_type not in ("memory_anomaly", "memory_scan"):
                return False
            ft = conditions.get("finding_type", "")
            return not ft or ft == event_finding_type

        return False

    def check_rate_limit(self, policy_id: int, max_per_window: int, window_seconds: int) -> bool:
        """Return True if within rate limit (execution allowed)."""
        now = time.time()
        if policy_id not in self._rate_limiter:
            self._rate_limiter[policy_id] = deque(maxlen=max_per_window * 2)

        timestamps = self._rate_limiter[policy_id]
        # Prune old entries
        while timestamps and now - timestamps[0] > window_seconds:
            timestamps.popleft()

        if len(timestamps) >= max_per_window:
            return False
        timestamps.append(now)
        return True

    async def evaluate_event(self, event: dict, remediation_engine=None, db_factory=None) -> list[dict]:
        """Evaluate event against all policies. Returns actions taken."""
        self._stats["total_evaluations"] += 1

        if not self._enabled or self._global_lockout:
            return []

        actions_taken = []
        for policy in self._policies:
            if not policy.get("enabled", True):
                continue

            if not self.matches_condition(policy, event):
                continue

            policy_id = policy.get("id", 0)
            rate_limit = policy.get("rate_limit", {}) or {}
            max_per_window = rate_limit.get("max", 5)
            window = rate_limit.get("window", 300)

            if not self.check_rate_limit(policy_id, max_per_window, window):
                self._stats["total_rate_limited"] += 1
                self._logger.info("sword_rate_limited", policy=policy.get("codename", "?"))
                continue

            # Cooldown check
            cooldown = policy.get("cooldown_seconds", 300)
            last_triggered = policy.get("_last_triggered_ts", 0)
            if time.time() - last_triggered < cooldown:
                continue

            result = await self.execute_policy(policy, event, remediation_engine, db_factory)
            actions_taken.append(result)

        return actions_taken

    async def execute_policy(self, policy: dict, event: dict, remediation_engine=None, db_factory=None) -> dict:
        """Execute escalation chain via RemediationEngine."""
        import time as _time
        start = _time.monotonic()
        codename = policy.get("codename", "UNKNOWN")
        escalation_chain = policy.get("escalation_chain", [])
        actions_results = []
        escalation_level = 0

        for action in escalation_chain:
            escalation_level += 1
            action_type = action.get("type", "")
            target = action.get("target", "")

            # Resolve target variables from event
            if target.startswith("$"):
                parts = target.lstrip("$").split(".")
                val = event
                for p in parts:
                    if isinstance(val, dict):
                        val = val.get(p, "")
                    else:
                        val = ""
                        break
                target = str(val) if val else ""

            result = {"action": action_type, "target": target, "status": "skipped"}

            if remediation_engine and target:
                try:
                    if action_type == "kill_process":
                        pid = int(target) if target.isdigit() else 0
                        if pid > 0:
                            r = await remediation_engine.kill_process(pid, reason=f"Sword Protocol: {codename}")
                            result["status"] = "success" if r.get("success") else "failed"
                    elif action_type == "block_ip":
                        duration = action.get("duration", 3600)
                        r = await remediation_engine.block_ip(target, duration=duration, reason=f"Sword Protocol: {codename}")
                        result["status"] = "success" if r.get("success") else "failed"
                    elif action_type == "quarantine_file":
                        r = await remediation_engine.quarantine_file(target, reason=f"Sword Protocol: {codename}")
                        result["status"] = "success" if r.get("success") else "failed"
                    elif action_type == "isolate_network":
                        r = await remediation_engine.isolate_network(target, reason=f"Sword Protocol: {codename}")
                        result["status"] = "success" if r.get("success") else "failed"
                    else:
                        result["status"] = "unknown_action"
                except Exception as e:
                    result["status"] = "error"
                    result["error"] = str(e)

            actions_results.append(result)

        duration_ms = int((_time.monotonic() - start) * 1000)
        overall = "success" if all(a["status"] == "success" for a in actions_results if a["status"] != "skipped") else "partial"
        if all(a["status"] in ("failed", "error", "skipped") for a in actions_results):
            overall = "failed"
            self._stats["total_failed"] += 1
        else:
            self._stats["total_strikes"] += 1

        self._stats["last_strike"] = datetime.now(timezone.utc).isoformat()
        policy["_last_triggered_ts"] = time.time()

        log_entry = {
            "policy_id": policy.get("id", 0),
            "codename": codename,
            "trigger_event": {k: v for k, v in event.items() if k in ("severity", "module_source", "title", "event_type", "rule_id")},
            "actions_taken": actions_results,
            "result": overall,
            "escalation_level": escalation_level,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": duration_ms,
        }
        self._execution_log.appendleft(log_entry)

        # Persist to DB
        if db_factory:
            try:
                from ..models.sword_execution_log import SwordExecutionLog
                async with db_factory() as session:
                    db_log = SwordExecutionLog(
                        policy_id=policy.get("id", 0),
                        codename=codename,
                        trigger_event_json=json.dumps(log_entry["trigger_event"]),
                        actions_taken_json=json.dumps(actions_results),
                        result=overall,
                        escalation_level=escalation_level,
                        duration_ms=duration_ms,
                    )
                    session.add(db_log)
                    # Update policy execution count
                    from ..models.sword_policy import SwordPolicy
                    from sqlalchemy import select as sa_select
                    pol_result = await session.execute(
                        sa_select(SwordPolicy).where(SwordPolicy.id == policy.get("id", 0))
                    )
                    db_policy = pol_result.scalar_one_or_none()
                    if db_policy:
                        db_policy.execution_count = (db_policy.execution_count or 0) + 1
                        db_policy.last_triggered = datetime.now(timezone.utc)
                    await session.commit()
            except Exception as e:
                self._logger.error("sword_log_persist_failed", error=str(e))

        self._logger.info(
            "sword_strike",
            codename=codename,
            result=overall,
            escalation_level=escalation_level,
            duration_ms=duration_ms,
        )
        return log_entry

    def test_policy(self, policy_id: int, test_event: dict) -> dict:
        """Dry-run a policy — evaluate without striking."""
        for policy in self._policies:
            if policy.get("id") == policy_id:
                matches = self.matches_condition(policy, test_event)
                rate_ok = True
                rate_limit = policy.get("rate_limit", {}) or {}
                if rate_limit:
                    # Don't actually consume rate limit
                    now = time.time()
                    timestamps = self._rate_limiter.get(policy_id, deque())
                    window = rate_limit.get("window", 300)
                    recent = sum(1 for t in timestamps if now - t <= window)
                    rate_ok = recent < rate_limit.get("max", 5)
                return {
                    "would_trigger": matches,
                    "rate_limit_ok": rate_ok,
                    "enabled": policy.get("enabled", True),
                    "sword_enabled": self._enabled,
                    "lockout": self._global_lockout,
                    "escalation_chain": policy.get("escalation_chain", []),
                }
        return {"error": "Policy not found in memory"}

    async def load_policies(self, db_factory) -> None:
        """Load policies from database into memory."""
        try:
            from ..models.sword_policy import SwordPolicy
            from sqlalchemy import select as sa_select
            async with db_factory() as session:
                result = await session.execute(sa_select(SwordPolicy).order_by(SwordPolicy.id))
                policies = result.scalars().all()
                self._policies = []
                for p in policies:
                    self._policies.append({
                        "id": p.id,
                        "codename": p.codename,
                        "name": p.name,
                        "description": p.description,
                        "trigger_type": p.trigger_type,
                        "trigger_conditions": json.loads(p.trigger_conditions_json) if p.trigger_conditions_json else {},
                        "escalation_chain": json.loads(p.escalation_chain_json) if p.escalation_chain_json else [],
                        "cooldown_seconds": p.cooldown_seconds,
                        "rate_limit": json.loads(p.rate_limit_json) if p.rate_limit_json else None,
                        "enabled": p.enabled,
                        "requires_confirmation": p.requires_confirmation,
                        "_last_triggered_ts": 0,
                    })
            self._logger.info("sword_policies_loaded", count=len(self._policies))
        except Exception as e:
            self._logger.error("sword_policies_load_failed", error=str(e))


# ---------------------------------------------------------------------------
# Phase 15 Track 5: Overwatch Protocol — system integrity monitoring
# ---------------------------------------------------------------------------

class OverwatchProtocol:
    """Bond monitors Cereberus itself for tampering and health.

    Computes SHA-256 baselines of all backend Python files on startup,
    periodically re-checks. Any modification triggers critical alert.
    Also monitors DB integrity and module health.
    """

    def __init__(self, backend_dir: str | None = None) -> None:
        self._backend_dir = Path(backend_dir) if backend_dir else Path(__file__).resolve().parent.parent
        self._code_baselines: dict[str, str] = {}
        self._tamper_count: int = 0
        self._last_check: datetime | None = None
        self._check_interval: int = 600  # 10 minutes
        self._status: str = "uninitialized"
        self._logger = get_logger("overwatch_protocol")

    def compute_baselines(self) -> dict:
        """Hash all .py files in backend/. Run on startup."""
        import hashlib as _hl
        count = 0
        for py_file in self._backend_dir.rglob("*.py"):
            try:
                content = py_file.read_bytes()
                self._code_baselines[str(py_file)] = _hl.sha256(content).hexdigest()
                count += 1
            except (PermissionError, OSError):
                continue
        self._status = "active"
        self._last_check = datetime.now(timezone.utc)
        self._logger.info("overwatch_baselines_computed", file_count=count)
        return {"files_baselined": count}

    def check_integrity(self) -> dict:
        """Re-hash and compare. Returns tampering report."""
        import hashlib as _hl
        if not self._code_baselines:
            return {"status": "no_baselines", "tampered": [], "missing": [], "new": []}

        tampered = []
        missing = []
        new_files = []

        current_files = set()
        for py_file in self._backend_dir.rglob("*.py"):
            path_str = str(py_file)
            current_files.add(path_str)
            try:
                content = py_file.read_bytes()
                current_hash = _hl.sha256(content).hexdigest()
            except (PermissionError, OSError):
                continue

            if path_str in self._code_baselines:
                if current_hash != self._code_baselines[path_str]:
                    tampered.append(path_str)
            else:
                new_files.append(path_str)

        for baselined_path in self._code_baselines:
            if baselined_path not in current_files:
                missing.append(baselined_path)

        self._tamper_count += len(tampered)
        self._last_check = datetime.now(timezone.utc)

        report = {
            "status": "tampered" if tampered or missing else "clean",
            "tampered": tampered,
            "missing": missing,
            "new": new_files,
            "total_baselined": len(self._code_baselines),
            "tamper_count_total": self._tamper_count,
            "checked_at": self._last_check.isoformat(),
        }

        if tampered:
            self._logger.warning("overwatch_tampering_detected", tampered_files=tampered)
        if missing:
            self._logger.warning("overwatch_files_missing", missing_files=missing)

        return report

    def get_status(self) -> dict:
        """Return overwatch status for API/frontend."""
        return {
            "status": self._status,
            "files_baselined": len(self._code_baselines),
            "tamper_count": self._tamper_count,
            "last_check": self._last_check.isoformat() if self._last_check else None,
            "check_interval_seconds": self._check_interval,
        }
