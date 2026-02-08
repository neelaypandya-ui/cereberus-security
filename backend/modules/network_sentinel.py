"""Network Sentinel Module — monitors live network connections.

Polls psutil.net_connections() at a configurable interval, caches live connections,
flags suspicious ports, and provides stats for the API/dashboard.
"""

import asyncio
import subprocess
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import psutil

from .base_module import BaseModule


# Default suspicious ports associated with backdoors / C2 / common exploit tools
DEFAULT_SUSPICIOUS_PORTS = {
    4444, 5555, 1337, 31337, 6666, 6667, 12345, 27374,
    1234, 3127, 3128, 4443, 8443,
}

# Dangerous service ports — flag if LISTENING on 0.0.0.0 (exposed to network)
DANGEROUS_LISTEN_PORTS = {
    21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS",
    445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
}


class NetworkSentinel(BaseModule):
    """Monitors live network connections and flags suspicious activity."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="network_sentinel", config=config)

        cfg = config or {}
        self._poll_interval: int = cfg.get("poll_interval", 5)
        self._suspicious_ports: set[int] = set(
            cfg.get("suspicious_ports", DEFAULT_SUSPICIOUS_PORTS)
        )

        # In-memory caches
        self._connections: list[dict] = []
        self._flagged: list[dict] = []
        self._stats: dict = {}
        self._scan_task: Optional[asyncio.Task] = None
        self._last_scan: Optional[datetime] = None

        # Anomaly detection integration
        self._anomaly_detector = None
        self._ensemble_detector = None
        self._last_anomaly_result: Optional[dict] = None
        self._anomaly_events: deque[dict] = deque(maxlen=200)

        # Behavioral baseline integration
        self._behavioral_baseline = None

        # DB session factory for persisting anomaly events
        self._db_session_factory = None

        # IOC matcher integration (Phase 8)
        self._ioc_matcher = None
        self._ioc_matches: list[dict] = []

        # Ports already blocked by Cereberus firewall rules (skip flagging these)
        self._cereberus_blocked_ports: set[int] = set()
        self._blocked_ports_last_check: float = 0

        # Warmup grace period — suppress anomaly alerts while model trains on real data
        self._warmup_seconds: int = cfg.get("anomaly_warmup_seconds", 1800)
        self._started_at: float = 0.0

    async def start(self) -> None:
        """Start the connection monitoring loop."""
        self.running = True
        self.health_status = "running"
        self._started_at = time.monotonic()
        self.logger.info("network_sentinel_starting")

        # Run initial scan
        await self._scan_connections()

        # Start polling loop
        self._scan_task = asyncio.create_task(self._poll_loop())
        self.heartbeat()
        self.logger.info("network_sentinel_started")

    async def stop(self) -> None:
        """Stop the monitoring loop."""
        self.running = False
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        self.health_status = "stopped"
        self.logger.info("network_sentinel_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "total_connections": self._stats.get("total", 0),
                "flagged_count": len(self._flagged),
                "last_scan": self._last_scan.isoformat() if self._last_scan else None,
            },
        }

    async def _poll_loop(self) -> None:
        """Periodically scan connections."""
        while self.running:
            try:
                await asyncio.sleep(self._poll_interval)
                if self.running:
                    await self._scan_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("network_scan_error", error=str(e))
                await asyncio.sleep(self._poll_interval)

    async def _scan_connections(self) -> None:
        """Scan current network connections via psutil."""
        loop = asyncio.get_event_loop()

        # Refresh Cereberus firewall rule cache (every 60s)
        await loop.run_in_executor(None, self._refresh_cereberus_blocked_ports)

        raw_conns = await loop.run_in_executor(
            None, lambda: psutil.net_connections(kind="inet")
        )

        connections = []
        flagged = []
        stats = {
            "total": 0,
            "established": 0,
            "listening": 0,
            "time_wait": 0,
            "close_wait": 0,
            "suspicious": 0,
            "tcp": 0,
            "udp": 0,
        }

        for conn in raw_conns:
            entry = self._parse_connection(conn)
            connections.append(entry)

            stats["total"] += 1
            status_lower = entry["status"].lower()
            if status_lower == "established":
                stats["established"] += 1
            elif status_lower == "listen":
                stats["listening"] += 1
            elif status_lower == "time_wait":
                stats["time_wait"] += 1
            elif status_lower == "close_wait":
                stats["close_wait"] += 1

            if entry["protocol"] == "tcp":
                stats["tcp"] += 1
            else:
                stats["udp"] += 1

            if entry["suspicious"]:
                stats["suspicious"] += 1
                flagged.append(entry)

        self._connections = connections
        self._flagged = flagged
        self._stats = stats
        self._last_scan = datetime.now(timezone.utc)

        # Feed behavioral baseline engine with connection counts
        if self._behavioral_baseline:
            try:
                ts = self._last_scan
                await self._behavioral_baseline.update("total_connections", float(stats["total"]), ts)
                await self._behavioral_baseline.update("established_connections", float(stats["established"]), ts)
                await self._behavioral_baseline.update("suspicious_connections", float(stats["suspicious"]), ts)
            except Exception as e:
                self.logger.error("baseline_update_error", error=str(e))

        # Check for behavioral deviations
        if self._behavioral_baseline:
            try:
                for metric_name, metric_value in [
                    ("total_connections", float(stats["total"])),
                    ("established_connections", float(stats["established"])),
                    ("suspicious_connections", float(stats["suspicious"])),
                ]:
                    deviation = self._behavioral_baseline.get_deviation_score(metric_name, metric_value)
                    if deviation and deviation.get("is_deviation"):
                        event = {
                            "timestamp": self._last_scan.isoformat(),
                            "anomaly_score": abs(deviation.get("z_score", 0)) / 10.0,
                            "threshold": 0.3,
                            "detector_type": "behavioral_baseline",
                            "metric": metric_name,
                            "value": metric_value,
                            "z_score": deviation.get("z_score", 0),
                            "stats": {"total": stats["total"], "suspicious": stats["suspicious"], "established": stats["established"]},
                        }
                        self._anomaly_events.append(event)
                        if self._db_session_factory:
                            await self._persist_baseline_deviation(event)
                        self.logger.warning(
                            "baseline_deviation_detected",
                            metric=metric_name,
                            z_score=deviation.get("z_score", 0),
                        )
            except Exception as e:
                self.logger.error("baseline_deviation_check_error", error=str(e))

        # Check remote IPs against IOC database
        if self._ioc_matcher:
            try:
                remote_ips = list({
                    c["remote_addr"] for c in connections
                    if c["remote_addr"] and c["remote_addr"] not in ("", "0.0.0.0", "127.0.0.1", "::1", "::")
                })
                if remote_ips:
                    matches = await self._ioc_matcher.check_ips(remote_ips)
                    if matches:
                        self._ioc_matches = matches
                        for match in matches:
                            # Mark matching connections as suspicious
                            for c in connections:
                                if c["remote_addr"] == match.get("value"):
                                    c["suspicious"] = True
                                    c["ioc_match"] = True
                            self.logger.warning(
                                "ioc_match_found",
                                ip=match.get("value"),
                                severity=match.get("severity"),
                            )
            except Exception as e:
                self.logger.error("ioc_check_error", error=str(e))

        # Run ensemble anomaly detection if available, else fallback to single detector
        if self._ensemble_detector:
            try:
                from ..ai.anomaly_detector import AnomalyDetector
                # Use autoencoder feature extraction
                detector = self._anomaly_detector or (
                    self._ensemble_detector._autoencoder
                    if hasattr(self._ensemble_detector, '_autoencoder') else None
                )
                if detector and hasattr(detector, 'extract_features'):
                    features = detector.extract_features(connections)
                    result = await self._ensemble_detector.predict(features)
                    result["timestamp"] = self._last_scan.isoformat()
                    result["stats_snapshot"] = {
                        "total": stats["total"],
                        "suspicious": stats["suspicious"],
                        "established": stats["established"],
                    }
                    self._last_anomaly_result = result
                    in_warmup = (time.monotonic() - self._started_at) < self._warmup_seconds
                    if result.get("is_anomaly") and not in_warmup:
                        import json
                        event = {
                            "timestamp": self._last_scan.isoformat(),
                            "anomaly_score": result.get("ensemble_score", 0),
                            "threshold": 0.5,
                            "detector_scores": result.get("detector_scores", {}),
                            "agreeing_detectors": result.get("agreeing_detectors", []),
                            "confidence": result.get("confidence", 0),
                            "explanation": result.get("explanation", ""),
                            "feature_attribution": result.get("feature_attribution", {}),
                            "stats": result["stats_snapshot"],
                        }
                        self._anomaly_events.append(event)

                        # Persist to DB if session factory available
                        if self._db_session_factory:
                            try:
                                await self._persist_anomaly_event(event, features)
                            except Exception as pe:
                                self.logger.error("anomaly_persist_error", error=str(pe))

                        self.logger.warning(
                            "ensemble_anomaly_detected",
                            score=result.get("ensemble_score", 0),
                            agreeing=result.get("agreeing_detectors", []),
                        )
                    elif result.get("is_anomaly") and in_warmup:
                        self.logger.info(
                            "anomaly_suppressed_warmup",
                            score=result.get("ensemble_score", 0),
                            remaining_s=int(self._warmup_seconds - (time.monotonic() - self._started_at)),
                        )
            except Exception as e:
                self.logger.error("ensemble_detection_error", error=str(e))
        elif self._anomaly_detector and self._anomaly_detector.initialized:
            try:
                features = self._anomaly_detector.extract_features(connections)
                result = await self._anomaly_detector.predict(features)
                result["timestamp"] = self._last_scan.isoformat()
                result["stats_snapshot"] = {
                    "total": stats["total"],
                    "suspicious": stats["suspicious"],
                    "established": stats["established"],
                }
                self._last_anomaly_result = result
                in_warmup = (time.monotonic() - self._started_at) < self._warmup_seconds
                if result.get("is_anomaly") and not in_warmup:
                    event = {
                        "timestamp": self._last_scan.isoformat(),
                        "anomaly_score": result["anomaly_score"],
                        "threshold": result["threshold"],
                        "stats": result["stats_snapshot"],
                    }
                    self._anomaly_events.append(event)
                    self.logger.warning(
                        "anomaly_detected",
                        score=result["anomaly_score"],
                        threshold=result["threshold"],
                    )
            except Exception as e:
                self.logger.error("anomaly_detection_error", error=str(e))

        self.heartbeat()

    def _parse_connection(self, conn) -> dict:
        """Parse a psutil connection into a serializable dict."""
        local_addr = ""
        local_port = None
        remote_addr = ""
        remote_port = None

        if conn.laddr:
            local_addr = conn.laddr.ip if hasattr(conn.laddr, "ip") else str(conn.laddr[0])
            local_port = conn.laddr.port if hasattr(conn.laddr, "port") else conn.laddr[1]

        if conn.raddr:
            remote_addr = conn.raddr.ip if hasattr(conn.raddr, "ip") else str(conn.raddr[0])
            remote_port = conn.raddr.port if hasattr(conn.raddr, "port") else conn.raddr[1]

        proto = "tcp" if conn.type == 1 else "udp"
        status = conn.status if hasattr(conn, "status") else "NONE"

        suspicious = self._is_suspicious(local_port, remote_port)

        # Flag dangerous services listening on all interfaces (exposed to network)
        # Skip ports already blocked by Cereberus firewall rules
        dangerous_service = None
        if status == "LISTEN" and local_addr in ("0.0.0.0", "::") and local_port in DANGEROUS_LISTEN_PORTS:
            if local_port not in self._cereberus_blocked_ports:
                suspicious = True
                dangerous_service = DANGEROUS_LISTEN_PORTS[local_port]

        return {
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "protocol": proto,
            "status": status,
            "pid": conn.pid,
            "suspicious": suspicious,
            "dangerous_service": dangerous_service,
        }

    def _refresh_cereberus_blocked_ports(self) -> None:
        """Refresh the set of ports blocked by Cereberus firewall rules. Cached for 60s."""
        import time
        now = time.monotonic()
        if now - self._blocked_ports_last_check < 60:
            return
        self._blocked_ports_last_check = now
        blocked = set()
        for port in DANGEROUS_LISTEN_PORTS:
            try:
                rule_name = f"CEREBERUS_BLOCK_PORT_{port}"
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and "Action:" in result.stdout:
                    blocked.add(port)
            except Exception:
                pass
        self._cereberus_blocked_ports = blocked

    def _is_suspicious(self, local_port: int | None, remote_port: int | None) -> bool:
        """Check if either port is in the suspicious set."""
        if local_port and local_port in self._suspicious_ports:
            return True
        if remote_port and remote_port in self._suspicious_ports:
            return True
        return False

    async def _persist_anomaly_event(self, event: dict, features=None) -> None:
        """Persist an anomaly event to the database."""
        import json
        from ..models.anomaly_event import AnomalyEvent

        async with self._db_session_factory() as session:
            record = AnomalyEvent(
                detector_type="ensemble",
                anomaly_score=event.get("anomaly_score", 0.0),
                threshold=event.get("threshold", 0.5),
                is_anomaly=True,
                feature_vector_json=json.dumps(features.tolist() if features is not None else []),
                feature_attribution_json=json.dumps(event.get("feature_attribution", {})),
                explanation=event.get("explanation", ""),
                confidence=event.get("confidence", 0.0),
                detector_scores_json=json.dumps(event.get("detector_scores", {})),
                context_json=json.dumps(event.get("stats", {})),
            )
            session.add(record)
            await session.commit()

    async def _persist_baseline_deviation(self, event: dict) -> None:
        """Persist a behavioral baseline deviation event."""
        import json
        from ..models.anomaly_event import AnomalyEvent

        try:
            async with self._db_session_factory() as session:
                record = AnomalyEvent(
                    detector_type="behavioral_baseline",
                    anomaly_score=event.get("anomaly_score", 0.0),
                    threshold=event.get("threshold", 0.3),
                    is_anomaly=True,
                    explanation=f"Behavioral deviation in {event.get('metric', 'unknown')}: z_score={event.get('z_score', 0):.2f}",
                    confidence=min(abs(event.get("z_score", 0)) / 5.0, 1.0),
                    context_json=json.dumps(event.get("stats", {})),
                )
                session.add(record)
                await session.commit()
        except Exception as e:
            self.logger.error("baseline_deviation_persist_error", error=str(e))

    # --- Anomaly detector integration ---

    def set_anomaly_detector(self, detector) -> None:
        """Attach an AnomalyDetector instance for live prediction."""
        self._anomaly_detector = detector
        self.logger.info("anomaly_detector_attached")

    def set_ensemble_detector(self, detector) -> None:
        """Attach an EnsembleDetector for multi-model prediction."""
        self._ensemble_detector = detector
        self.logger.info("ensemble_detector_attached")

    def set_behavioral_baseline(self, engine) -> None:
        """Attach the behavioral baseline engine."""
        self._behavioral_baseline = engine
        self.logger.info("behavioral_baseline_attached")

    def set_db_session_factory(self, factory) -> None:
        """Attach a DB session factory for anomaly event persistence."""
        self._db_session_factory = factory
        self.logger.info("db_session_factory_attached")

    def set_ioc_matcher(self, matcher) -> None:
        """Attach an IOCMatcher for checking IPs against threat feeds."""
        self._ioc_matcher = matcher
        self.logger.info("ioc_matcher_attached")

    def get_ioc_matches(self) -> list[dict]:
        """Return recent IOC matches from network scans."""
        return self._ioc_matches

    def get_anomaly_result(self) -> Optional[dict]:
        """Return the most recent anomaly detection result.

        During the warmup grace period, is_anomaly is masked to False
        so that downstream consumers (e.g. threat_intelligence) do not
        create alerts from an undertrained model.
        """
        if self._last_anomaly_result is None:
            return None
        in_warmup = (time.monotonic() - self._started_at) < self._warmup_seconds
        if in_warmup and self._last_anomaly_result.get("is_anomaly"):
            return {**self._last_anomaly_result, "is_anomaly": False, "warmup": True}
        return self._last_anomaly_result

    def get_anomaly_events(self, limit: int = 50) -> list[dict]:
        """Return recent anomaly events (where is_anomaly=True)."""
        events = list(self._anomaly_events)
        return events[-limit:]

    # --- Public API methods ---

    def get_live_connections(self) -> list[dict]:
        """Return all cached live connections."""
        return self._connections

    def get_stats(self) -> dict:
        """Return connection statistics."""
        return {
            **self._stats,
            "last_scan": self._last_scan.isoformat() if self._last_scan else None,
        }

    def get_flagged_connections(self) -> list[dict]:
        """Return only flagged (suspicious) connections."""
        return self._flagged
