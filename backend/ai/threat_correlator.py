"""Threat Correlator — correlates events across modules to detect attack patterns.

Uses rolling event buffers and attack pattern templates to identify
multi-stage attacks and coordinated threat activity.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from ..utils.logging import get_logger

logger = get_logger("ai.threat_correlator")


@dataclass
class SecurityEvent:
    """A security event from any module."""
    event_type: str  # e.g., "suspicious_connection", "brute_force", "file_change"
    source_module: str
    severity: str  # critical, high, medium, low, info
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict = field(default_factory=dict)


@dataclass
class AttackPattern:
    """Template for a known attack pattern."""
    name: str
    required_events: list[str]  # event types that must appear
    time_window: timedelta  # max time span for all events
    min_events: int  # minimum number of required event types that must match
    threat_level: str  # resulting threat level if matched
    description: str = ""


# Predefined attack patterns
ATTACK_PATTERNS = [
    AttackPattern(
        name="potential_compromise",
        required_events=["brute_force_detected", "suspicious_connection", "file_change"],
        time_window=timedelta(minutes=30),
        min_events=3,
        threat_level="critical",
        description="Brute force followed by suspicious connection and file changes",
    ),
    AttackPattern(
        name="lateral_movement",
        required_events=["suspicious_connection", "new_process_suspicious", "port_scan"],
        time_window=timedelta(minutes=15),
        min_events=2,
        threat_level="high",
        description="Suspicious connections combined with new suspicious processes",
    ),
    AttackPattern(
        name="phishing_attack",
        required_events=["phishing_detected", "suspicious_connection", "file_change"],
        time_window=timedelta(minutes=60),
        min_events=2,
        threat_level="high",
        description="Phishing content followed by suspicious network or file activity",
    ),
    AttackPattern(
        name="data_exfiltration",
        required_events=["suspicious_connection", "high_bandwidth", "file_change"],
        time_window=timedelta(minutes=20),
        min_events=2,
        threat_level="critical",
        description="Large data transfers to suspicious destinations",
    ),
    AttackPattern(
        name="reconnaissance",
        required_events=["port_scan", "suspicious_connection", "new_process_suspicious"],
        time_window=timedelta(minutes=10),
        min_events=2,
        threat_level="medium",
        description="Network scanning and enumeration activity detected",
    ),
    AttackPattern(
        name="anomaly_with_suspicious_connection",
        required_events=["anomaly_detected", "suspicious_connection"],
        time_window=timedelta(minutes=15),
        min_events=2,
        threat_level="high",
        description="AI-detected network anomaly combined with suspicious connections",
    ),
    AttackPattern(
        name="anomaly_brute_force_compromise",
        required_events=["anomaly_detected", "brute_force_detected", "file_change"],
        time_window=timedelta(minutes=30),
        min_events=3,
        threat_level="critical",
        description="Network anomaly with brute force and file modifications indicating active compromise",
    ),
    AttackPattern(
        name="persistence_after_compromise",
        required_events=["persistence_change", "brute_force_detected", "suspicious_connection"],
        time_window=timedelta(minutes=60),
        min_events=3,
        threat_level="critical",
        description="New persistence mechanism installed after brute force and suspicious network activity",
    ),
    AttackPattern(
        name="resource_abuse_attack",
        required_events=["resource_spike", "suspicious_connection", "anomaly_detected"],
        time_window=timedelta(minutes=15),
        min_events=2,
        threat_level="high",
        description="Resource spike combined with suspicious network activity suggesting cryptominer or DDoS",
    ),
    AttackPattern(
        name="vulnerability_exploitation",
        required_events=["vulnerability_found", "suspicious_connection", "file_change"],
        time_window=timedelta(minutes=60),
        min_events=2,
        threat_level="critical",
        description="Known vulnerability exploited through network connection with file system changes",
    ),
]


class ThreatCorrelator:
    """Correlates security events to detect complex attack patterns."""

    def __init__(self, max_events: int = 1000, max_age_hours: float = 1.0):
        self.initialized = False
        self._max_events = max_events
        self._max_age = timedelta(hours=max_age_hours)
        self._events: deque[SecurityEvent] = deque(maxlen=max_events)
        self._correlations: list[dict] = []
        self._patterns = list(ATTACK_PATTERNS)

    async def initialize(self) -> None:
        self.initialized = True

    def add_event(self, event: SecurityEvent) -> None:
        """Add a security event to the rolling buffer."""
        self._events.append(event)
        self._prune_old_events()

    def add_event_dict(self, event_type: str, source_module: str,
                       severity: str = "medium", details: dict | None = None) -> None:
        """Convenience method to add an event from raw parameters."""
        event = SecurityEvent(
            event_type=event_type,
            source_module=source_module,
            severity=severity,
            details=details or {},
        )
        self.add_event(event)

    def _prune_old_events(self) -> None:
        """Remove events older than max_age."""
        cutoff = datetime.now(timezone.utc) - self._max_age
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()

    async def correlate(self, events: list[dict] | None = None) -> dict:
        """Run correlation analysis on the event buffer.

        Args:
            events: Optional list of event dicts to add before correlating.

        Returns:
            Dict with threat_level, correlations list, event_count.
        """
        if events:
            for e in events:
                self.add_event_dict(
                    event_type=e.get("event_type", "unknown"),
                    source_module=e.get("source_module", "unknown"),
                    severity=e.get("severity", "medium"),
                    details=e.get("details", {}),
                )

        self._prune_old_events()
        correlations = self._check_patterns()
        self._correlations = correlations

        # Determine overall threat level from highest correlation
        threat_level = "none"
        level_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        for corr in correlations:
            if level_order.get(corr["threat_level"], 0) > level_order.get(threat_level, 0):
                threat_level = corr["threat_level"]

        # Also factor in raw event severity
        if not correlations and self._events:
            severities = [e.severity for e in self._events]
            if severities.count("critical") >= 2:
                threat_level = "high"
            elif "critical" in severities:
                threat_level = "medium"
            elif severities.count("high") >= 3:
                threat_level = "medium"
            elif "high" in severities:
                threat_level = "low"

        return {
            "threat_level": threat_level,
            "correlations": correlations,
            "event_count": len(self._events),
        }

    def _check_patterns(self) -> list[dict]:
        """Check all attack patterns against current event buffer."""
        now = datetime.now(timezone.utc)
        correlations = []

        for pattern in self._patterns:
            window_start = now - pattern.time_window
            window_events = [
                e for e in self._events if e.timestamp >= window_start
            ]

            event_types_present = set(e.event_type for e in window_events)
            matched_types = [
                et for et in pattern.required_events if et in event_types_present
            ]

            if len(matched_types) >= pattern.min_events:
                matched_events = [
                    {
                        "event_type": e.event_type,
                        "source_module": e.source_module,
                        "severity": e.severity,
                        "timestamp": e.timestamp.isoformat(),
                        "details": e.details,
                    }
                    for e in window_events
                    if e.event_type in matched_types
                ]

                correlations.append({
                    "pattern": pattern.name,
                    "threat_level": pattern.threat_level,
                    "description": pattern.description,
                    "matched_event_types": matched_types,
                    "matched_events": matched_events,
                    "window": str(pattern.time_window),
                })

        return correlations

    def get_event_buffer(self, limit: int = 100) -> list[dict]:
        """Get recent events from buffer."""
        events = list(self._events)[-limit:]
        return [
            {
                "event_type": e.event_type,
                "source_module": e.source_module,
                "severity": e.severity,
                "timestamp": e.timestamp.isoformat(),
                "details": e.details,
            }
            for e in reversed(events)
        ]

    def get_correlations(self) -> list[dict]:
        """Get latest correlation results."""
        return self._correlations
