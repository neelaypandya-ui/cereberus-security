"""IOC Confidence Score Normalization — normalizes scores from various sources to 0-100."""

from ..utils.logging import get_logger

logger = get_logger("intel.confidence")


class ConfidenceScorer:
    """Static methods to normalize confidence scores from various threat intel sources."""

    @staticmethod
    def from_virustotal(stats: dict) -> int:
        """Normalize VirusTotal scan stats to 0-100 confidence.

        stats should have 'malicious', 'suspicious', 'undetected', 'harmless' counts.
        """
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = malicious + suspicious + stats.get("undetected", 0) + stats.get("harmless", 0)
        if total == 0:
            return 0
        # Weight: malicious=1.0, suspicious=0.5
        score = ((malicious + suspicious * 0.5) / total) * 100
        return min(100, max(0, int(score)))

    @staticmethod
    def from_abuseipdb(abuse_score: int) -> int:
        """AbuseIPDB score is already 0-100, pass through."""
        return min(100, max(0, abuse_score))

    @staticmethod
    def from_threatfox(confidence_level: int | None) -> int:
        """ThreatFox uses confidence_level 0-100, pass through with default."""
        if confidence_level is None:
            return 50  # Default medium confidence
        return min(100, max(0, confidence_level))

    @staticmethod
    def from_feed_severity(severity: str) -> int:
        """Map severity string to confidence score."""
        mapping = {
            "critical": 95,
            "high": 80,
            "medium": 60,
            "low": 40,
            "info": 20,
        }
        return mapping.get(severity.lower(), 50)

    @staticmethod
    def weighted_update(existing_confidence: int | None, new_confidence: int, weight: float = 0.3) -> int:
        """Update confidence with weighted average (new evidence)."""
        if existing_confidence is None:
            return new_confidence
        updated = existing_confidence * (1 - weight) + new_confidence * weight
        return min(100, max(0, int(updated)))
