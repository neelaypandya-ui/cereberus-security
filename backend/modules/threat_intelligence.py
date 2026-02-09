"""Threat Intelligence Module — aggregates and correlates security events.

Meta-module that collects events from all other running modules and feeds
them into the ThreatCorrelator for pattern matching and threat level assessment.
"""

import asyncio
import time
from datetime import datetime, timezone
from typing import Optional

from .base_module import BaseModule


class ThreatIntelligence(BaseModule):
    """Aggregates security events from all modules and correlates threats."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="threat_intelligence", config=config)

        cfg = config or {}
        self._poll_interval: int = cfg.get("poll_interval", 15)
        self._feed_max: int = cfg.get("feed_max_events", 1000)
        self._correlation_window: float = cfg.get("correlation_window", 1.0)

        self._correlator = None
        self._module_refs: dict = {}
        self._threat_level: str = "none"
        self._threat_feed: list[dict] = []
        self._correlations: list[dict] = []
        self._poll_task: Optional[asyncio.Task] = None
        self._last_poll: Optional[datetime] = None

        # Track already-reported suspicious PIDs to avoid re-alerting
        self._seen_suspicious_pids: set[int] = set()

        # Anomaly alert dedup — don't re-alert for the same event type within cooldown
        # Read from config if available; default 30 minutes (1800 seconds)
        try:
            from ..dependencies import get_app_config
            _app_cfg = get_app_config()
            self._anomaly_alert_cooldown: float = float(
                getattr(_app_cfg, "anomaly_cooldown_minutes", 30)
            ) * 60.0
        except Exception:
            self._anomaly_alert_cooldown: float = 1800.0
        self._last_anomaly_alert_time: dict[str, float] = {}

        # Phase 7 integrations
        self._playbook_executor = None
        self._incident_manager = None
        self._alert_manager = None

        # Phase 11: Rule engine for immediate detection
        self._rule_engine = None

    def set_module_refs(self, refs: dict) -> None:
        """Set references to other running modules.

        Args:
            refs: Dict mapping module names to module instances, e.g.:
                {"network_sentinel": ns, "brute_force_shield": bfs, ...}
        """
        self._module_refs = refs
        self.logger.info("threat_intel_module_refs_set", modules=list(refs.keys()))

    def set_playbook_executor(self, executor) -> None:
        """Attach the PlaybookExecutor for automated responses."""
        self._playbook_executor = executor
        self.logger.info("playbook_executor_attached")

    def set_incident_manager(self, manager) -> None:
        """Attach the IncidentManager for auto-incident creation."""
        self._incident_manager = manager
        self.logger.info("incident_manager_attached")

    def set_alert_manager(self, manager) -> None:
        """Attach the AlertManager for creating persistent alerts."""
        self._alert_manager = manager
        self.logger.info("alert_manager_attached")

    def set_rule_engine(self, engine) -> None:
        """Attach the RuleEngine for rule-based detection."""
        self._rule_engine = engine
        self.logger.info("rule_engine_attached")

    def _ensure_correlator(self):
        if self._correlator is None:
            from ..ai.threat_correlator import ThreatCorrelator
            self._correlator = ThreatCorrelator(
                max_events=self._feed_max,
                max_age_hours=self._correlation_window,
            )

    async def start(self) -> None:
        self.running = True
        self.health_status = "running"
        self._ensure_correlator()
        self.logger.info("threat_intelligence_starting")

        self._poll_task = asyncio.create_task(self._poll_loop())
        self.heartbeat()
        self.logger.info("threat_intelligence_started")

    async def stop(self) -> None:
        self.running = False
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        self.health_status = "stopped"
        self.logger.info("threat_intelligence_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "threat_level": self._threat_level,
                "event_count": len(self._threat_feed),
                "correlation_count": len(self._correlations),
                "last_poll": self._last_poll.isoformat() if self._last_poll else None,
            },
        }

    async def _poll_loop(self) -> None:
        while self.running:
            try:
                await asyncio.sleep(self._poll_interval)
                if self.running:
                    await self._collect_and_correlate()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("threat_intel_poll_error", error=str(e))
                await asyncio.sleep(self._poll_interval)

    async def _collect_and_correlate(self) -> None:
        """Collect events from all modules and run correlation."""
        self._ensure_correlator()
        events = []

        # Collect from Network Sentinel
        ns = self._module_refs.get("network_sentinel")
        if ns:
            try:
                flagged = ns.get_flagged_connections()
                for conn in flagged:
                    events.append({
                        "event_type": "suspicious_connection",
                        "source_module": "network_sentinel",
                        "severity": "high",
                        "details": conn,
                    })
            except Exception:
                pass

            # Collect anomaly results (with 30-min cooldown to prevent alert spam)
            try:
                anomaly = ns.get_anomaly_result() if hasattr(ns, "get_anomaly_result") else None
                if anomaly and anomaly.get("is_anomaly"):
                    now = time.monotonic()
                    last = self._last_anomaly_alert_time.get("network_sentinel", 0)
                    if now - last >= self._anomaly_alert_cooldown:
                        self._last_anomaly_alert_time["network_sentinel"] = now
                        events.append({
                            "event_type": "anomaly_detected",
                            "source_module": "network_sentinel",
                            "severity": "high",
                            "details": {
                                "anomaly_score": anomaly.get("anomaly_score"),
                                "threshold": anomaly.get("threshold"),
                            },
                        })
            except Exception:
                pass

        # Collect from Brute Force Shield
        bfs = self._module_refs.get("brute_force_shield")
        if bfs:
            try:
                blocked = bfs.get_blocked_ips() if hasattr(bfs, "get_blocked_ips") else []
                for ip_info in blocked:
                    events.append({
                        "event_type": "brute_force_detected",
                        "source_module": "brute_force_shield",
                        "severity": "high",
                        "details": ip_info if isinstance(ip_info, dict) else {"ip": str(ip_info)},
                    })
            except Exception:
                pass

        # Collect from File Integrity
        fi = self._module_refs.get("file_integrity")
        if fi:
            try:
                changes = fi.get_changes() if hasattr(fi, "get_changes") else []
                for change in changes:
                    events.append({
                        "event_type": "file_change",
                        "source_module": "file_integrity",
                        "severity": "medium",
                        "details": change if isinstance(change, dict) else {"path": str(change)},
                    })
            except Exception:
                pass

        # Collect from Process Analyzer — only report newly-suspicious PIDs
        pa = self._module_refs.get("process_analyzer")
        if pa:
            try:
                suspicious = pa.get_suspicious()
                current_suspicious_pids = set()
                for proc in suspicious:
                    pid = proc.get("pid")
                    current_suspicious_pids.add(pid)
                    if pid not in self._seen_suspicious_pids:
                        events.append({
                            "event_type": "new_process_suspicious",
                            "source_module": "process_analyzer",
                            "severity": "high",
                            "details": proc,
                        })
                # Prune PIDs that are no longer suspicious
                self._seen_suspicious_pids = current_suspicious_pids
            except Exception:
                pass

        # Collect from Vulnerability Scanner
        vs = self._module_refs.get("vuln_scanner")
        if vs:
            try:
                vulns = vs.get_vulnerabilities() if hasattr(vs, "get_vulnerabilities") else []
                for vuln in vulns:
                    if vuln.get("severity") in ("critical", "high"):
                        events.append({
                            "event_type": "vulnerability_found",
                            "source_module": "vuln_scanner",
                            "severity": vuln.get("severity", "high"),
                            "details": {
                                "title": vuln.get("title"),
                                "category": vuln.get("category"),
                            },
                        })
            except Exception:
                pass

        # Collect from Persistence Scanner
        ps = self._module_refs.get("persistence_scanner")
        if ps:
            try:
                changes = ps.get_changes() if hasattr(ps, "get_changes") else []
                for change in changes:
                    events.append({
                        "event_type": "persistence_change",
                        "source_module": "persistence_scanner",
                        "severity": "high" if change.get("status") == "added" else "medium",
                        "details": change if isinstance(change, dict) else {"entry": str(change)},
                    })
            except Exception:
                pass

        # Collect from Resource Monitor
        rm = self._module_refs.get("resource_monitor")
        if rm:
            try:
                alerts = rm.get_alerts() if hasattr(rm, "get_alerts") else []
                for alert in alerts[-5:]:  # Only recent threshold alerts
                    events.append({
                        "event_type": "resource_spike",
                        "source_module": "resource_monitor",
                        "severity": "medium",
                        "details": alert if isinstance(alert, dict) else {"info": str(alert)},
                    })
            except Exception:
                pass

        # Collect from Event Log Monitor (Phase 11)
        elm = self._module_refs.get("event_log_monitor")
        if elm:
            try:
                critical_events = elm.get_recent_critical(limit=10)
                for evt in critical_events:
                    events.append({
                        "event_type": f"event_log_{evt.get('event_id', 'unknown')}",
                        "source_module": "event_log_monitor",
                        "severity": evt.get("severity", "high"),
                        "details": evt,
                    })
            except Exception:
                pass

        # Run Rule Engine on process and event log data (Phase 11)
        if self._rule_engine:
            try:
                # Evaluate process events
                if pa:
                    for proc in (pa.get_suspicious() or []):
                        matches = self._rule_engine.evaluate(proc)
                        for match in matches:
                            events.append({
                                "event_type": f"rule_match_{match.rule_id}",
                                "source_module": "rule_engine",
                                "severity": match.severity,
                                "details": {
                                    "rule_id": match.rule_id,
                                    "rule_name": match.rule_name,
                                    "category": match.category,
                                    "explanation": match.explanation,
                                },
                            })
                # Evaluate event log events
                if elm:
                    for evt in (elm.get_events(limit=20) or []):
                        matches = self._rule_engine.evaluate(evt)
                        for match in matches:
                            events.append({
                                "event_type": f"rule_match_{match.rule_id}",
                                "source_module": "rule_engine",
                                "severity": match.severity,
                                "details": {
                                    "rule_id": match.rule_id,
                                    "rule_name": match.rule_name,
                                    "category": match.category,
                                    "explanation": match.explanation,
                                },
                            })
            except Exception as re:
                self.logger.error("rule_engine_eval_error", error=str(re))

        # Feed events to correlator
        if events:
            result = await self._correlator.correlate(events)
            self._threat_level = result["threat_level"]
            self._correlations = result["correlations"]

            # Append to feed (trim to max)
            for e in events:
                e["timestamp"] = datetime.now(timezone.utc).isoformat()
            self._threat_feed = (events + self._threat_feed)[:self._feed_max]

            # Create persistent alerts for high/critical events
            if self._alert_manager:
                for event in events:
                    sev = event.get("severity", "info")
                    if sev in ("critical", "high"):
                        try:
                            await self._alert_manager.create_alert(
                                severity=sev,
                                module_source=event.get("source_module", "threat_intelligence"),
                                title=f"{event.get('event_type', 'security_event')}",
                                description=str(event.get("details", {}))[:500],
                                details=event.get("details"),
                            )
                        except Exception as ae:
                            self.logger.error("alert_create_error", error=str(ae))

            # Feed events to playbook executor for automated response
            if self._playbook_executor:
                for event in events:
                    try:
                        await self._playbook_executor.evaluate_event(event)
                    except Exception as pe:
                        self.logger.error("playbook_eval_error", error=str(pe))

            # Auto-create incidents from correlations
            if self._incident_manager and self._correlations:
                for corr in self._correlations:
                    try:
                        await self._incident_manager.auto_create_from_correlation(
                            corr, events
                        )
                    except Exception as ie:
                        self.logger.error("incident_auto_create_error", error=str(ie))

        self._last_poll = datetime.now(timezone.utc)
        self.heartbeat()

    # --- Public API ---

    def get_threat_level(self) -> str:
        return self._threat_level

    def get_threat_feed(self, limit: int = 100) -> list[dict]:
        return self._threat_feed[:limit]

    def get_correlations(self) -> list[dict]:
        return self._correlations
