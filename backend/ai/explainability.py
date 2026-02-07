"""AI Explainability — feature attribution and human-readable explanations.

Provides per-feature contribution analysis and natural language explanations
for anomaly detection results.
"""

import numpy as np

from ..utils.logging import get_logger

logger = get_logger("ai.explainability")

# Feature names matching AnomalyDetector.FEATURE_NAMES
FEATURE_NAMES = [
    "total_connections", "established_ratio", "listening_ratio",
    "time_wait_ratio", "close_wait_ratio", "tcp_ratio",
    "udp_ratio", "suspicious_ratio", "unique_remote_ips",
    "unique_local_ports", "unique_remote_ports", "avg_connections_per_ip",
]

# Human-readable descriptions for each feature
FEATURE_DESCRIPTIONS = {
    "total_connections": "total network connections",
    "established_ratio": "established connection ratio",
    "listening_ratio": "listening port ratio",
    "time_wait_ratio": "TIME_WAIT connection ratio",
    "close_wait_ratio": "CLOSE_WAIT connection ratio",
    "tcp_ratio": "TCP protocol ratio",
    "udp_ratio": "UDP protocol ratio",
    "suspicious_ratio": "suspicious connection ratio",
    "unique_remote_ips": "unique remote IP count",
    "unique_local_ports": "unique local port count",
    "unique_remote_ports": "unique remote port count",
    "avg_connections_per_ip": "average connections per IP",
}


class AnomalyExplainer:
    """Generates explanations for anomaly detection results."""

    def compute_attribution(
        self,
        features: np.ndarray,
        baseline_mean: np.ndarray | None,
        baseline_std: np.ndarray | None,
    ) -> dict[str, float]:
        """Compute per-feature contribution to the anomaly score.

        Uses the absolute deviation from baseline, normalized so contributions sum to 1.

        Args:
            features: 1D feature vector (12 values).
            baseline_mean: Per-feature mean from training data.
            baseline_std: Per-feature std from training data.

        Returns:
            Dict mapping feature_name -> contribution (0 to 1, sums to ~1).
        """
        if baseline_mean is None or baseline_std is None:
            # Without baseline, use equal attribution
            equal = 1.0 / len(FEATURE_NAMES)
            return {name: equal for name in FEATURE_NAMES}

        std_safe = np.where(baseline_std == 0, 1.0, baseline_std)
        deviations = np.abs(features - baseline_mean) / std_safe

        total = deviations.sum()
        if total == 0:
            equal = 1.0 / len(FEATURE_NAMES)
            return {name: equal for name in FEATURE_NAMES}

        normalized = deviations / total

        return {
            name: float(normalized[i])
            for i, name in enumerate(FEATURE_NAMES)
        }

    def generate_explanation(
        self,
        attribution: dict[str, float],
        detector_scores: dict[str, float],
        ensemble_result: dict,
    ) -> str:
        """Generate a human-readable explanation of the anomaly.

        Args:
            attribution: Feature attribution dict from compute_attribution().
            detector_scores: Per-detector anomaly scores.
            ensemble_result: Full ensemble result dict.

        Returns:
            Human-readable explanation string.
        """
        parts = []

        # Overall verdict
        is_anomaly = ensemble_result.get("is_anomaly", False)
        score = ensemble_result.get("ensemble_score", 0.0)
        agreeing = ensemble_result.get("agreeing_detectors", [])

        if is_anomaly:
            parts.append(f"ANOMALY DETECTED (ensemble score: {score:.3f}).")
        else:
            parts.append(f"Normal activity (ensemble score: {score:.3f}).")

        # Detector agreement
        if agreeing:
            parts.append(f"Flagged by: {', '.join(agreeing)}.")
        elif detector_scores:
            parts.append("No detector consensus reached.")

        # Top contributing features
        sorted_attrs = sorted(attribution.items(), key=lambda x: x[1], reverse=True)
        top_features = [(name, val) for name, val in sorted_attrs if val > 0.1][:3]

        if top_features:
            feature_strs = []
            for name, val in top_features:
                desc = FEATURE_DESCRIPTIONS.get(name, name)
                feature_strs.append(f"{desc} ({val:.0%})")
            parts.append(f"Primary drivers: {', '.join(feature_strs)}.")

        return " ".join(parts)

    def compute_confidence(
        self,
        detector_scores: dict[str, float],
        agreeing_count: int,
    ) -> float:
        """Compute confidence level for the ensemble decision.

        Args:
            detector_scores: Per-detector scores.
            agreeing_count: Number of detectors that agree on the verdict.

        Returns:
            Confidence float 0-1.
        """
        if not detector_scores:
            return 0.0

        total_detectors = len(detector_scores)
        if total_detectors == 0:
            return 0.0

        agreement_ratio = agreeing_count / total_detectors
        avg_score = sum(detector_scores.values()) / total_detectors

        # Confidence is higher when detectors agree and scores are consistent
        score_variance = np.var(list(detector_scores.values()))
        consistency = max(0.0, 1.0 - score_variance * 4)

        confidence = agreement_ratio * 0.5 + avg_score * 0.3 + consistency * 0.2
        return float(np.clip(confidence, 0.0, 1.0))
