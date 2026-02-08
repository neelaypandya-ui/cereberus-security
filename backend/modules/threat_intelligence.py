"""Threat Intelligence Module — aggregates and correlates security events.

Meta-module that collects events from all other running modules and feeds
them into the ThreatCorrelator for pattern matching and threat level assessment.
"""

import asyncio
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

        # Phase 7 integrations
        self._playbook_executor = None
        self._incident_manager = None
        self._alert_manager = None

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

            # Collect anomaly results
            try:
                anomaly = ns.get_anomaly_result() if hasattr(ns, "get_anomaly_result") else None
                if anomaly and anomaly.get("is_anomaly"):
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

        # Collect from Process Analyzer
        pa = self._module_refs.get("process_analyzer")
        if pa:
            try:
                suspicious = pa.get_suspicious()
                for proc in suspicious:
                    events.append({
                        "event_type": "new_process_suspicious",
                        "source_module": "process_analyzer",
                        "severity": "high",
                        "details": proc,
                    })
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
