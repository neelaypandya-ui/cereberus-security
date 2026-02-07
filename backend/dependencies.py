"""FastAPI dependency injection providers."""

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from .config import CereberusConfig, get_config
from .database import get_session
from .utils.security import decode_access_token

security_scheme = HTTPBearer()

_config_instance: CereberusConfig | None = None
_alert_manager = None
_vpn_guardian = None
_network_sentinel = None
_brute_force_shield = None
_file_integrity = None
_process_analyzer = None
_vuln_scanner = None
_email_analyzer = None
_threat_intelligence = None
_anomaly_detector = None
_nlp_analyzer = None
_threat_correlator = None


def get_app_config() -> CereberusConfig:
    """Get the application config singleton."""
    global _config_instance
    if _config_instance is None:
        _config_instance = get_config()
    return _config_instance


async def get_db(config: CereberusConfig = Depends(get_app_config)):
    """Get an async database session."""
    async for session in get_session(config):
        yield session


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    config: CereberusConfig = Depends(get_app_config),
) -> dict:
    """Validate JWT token and return current user."""
    payload = decode_access_token(
        credentials.credentials,
        config.secret_key,
        config.jwt_algorithm,
    )
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def get_alert_manager():
    """Get the alert manager singleton."""
    global _alert_manager
    if _alert_manager is None:
        from .alerting.manager import AlertManager
        config = get_app_config()
        _alert_manager = AlertManager(
            desktop_notifications=config.alert_desktop_notifications,
            webhook_url=config.alert_webhook_url,
        )
    return _alert_manager


def get_vpn_guardian():
    """Get the VPN Guardian module singleton."""
    global _vpn_guardian
    if _vpn_guardian is None:
        from .modules.vpn_guardian import VPNGuardian
        config = get_app_config()
        _vpn_guardian = VPNGuardian(config={
            "vpn_kill_switch_mode": config.vpn_kill_switch_mode,
            "vpn_leak_check_interval": config.vpn_leak_check_interval,
            "vpn_trusted_interfaces": config.vpn_trusted_interfaces,
            "vpn_trusted_dns": config.vpn_trusted_dns,
        })
    return _vpn_guardian


def get_network_sentinel():
    """Get the Network Sentinel module singleton."""
    global _network_sentinel
    if _network_sentinel is None:
        from .modules.network_sentinel import NetworkSentinel
        config = get_app_config()
        _network_sentinel = NetworkSentinel(config={
            "poll_interval": config.network_poll_interval,
            "suspicious_ports": config.network_suspicious_ports,
        })
    return _network_sentinel


def get_brute_force_shield():
    """Get the Brute Force Shield module singleton."""
    global _brute_force_shield
    if _brute_force_shield is None:
        from .modules.brute_force_shield import BruteForceShield
        config = get_app_config()
        _brute_force_shield = BruteForceShield(config={
            "poll_interval": config.brute_force_poll_interval,
            "threshold": config.brute_force_threshold,
            "window_seconds": config.brute_force_window_seconds,
            "block_duration": config.brute_force_block_duration,
            "whitelist_ips": config.brute_force_whitelist_ips,
        })
    return _brute_force_shield


def get_file_integrity():
    """Get the File Integrity module singleton."""
    global _file_integrity
    if _file_integrity is None:
        from .modules.file_integrity import FileIntegrity
        config = get_app_config()
        _file_integrity = FileIntegrity(config={
            "scan_interval": config.file_integrity_scan_interval,
            "watched_paths": config.file_integrity_watched_paths,
            "exclusion_patterns": config.file_integrity_exclusion_patterns,
            "max_file_size": config.file_integrity_max_file_size,
        })
    return _file_integrity


def get_process_analyzer():
    """Get the Process Analyzer module singleton."""
    global _process_analyzer
    if _process_analyzer is None:
        from .modules.process_analyzer import ProcessAnalyzer
        config = get_app_config()
        _process_analyzer = ProcessAnalyzer(config={
            "poll_interval": config.process_poll_interval,
            "suspicious_names": config.process_suspicious_names,
        })
    return _process_analyzer


def get_vuln_scanner():
    """Get the Vulnerability Scanner module singleton."""
    global _vuln_scanner
    if _vuln_scanner is None:
        from .modules.vuln_scanner import VulnScanner
        config = get_app_config()
        _vuln_scanner = VulnScanner(config={
            "scan_interval": config.vuln_scan_interval,
            "check_windows_updates": config.vuln_check_windows_updates,
            "check_open_ports": config.vuln_check_open_ports,
            "check_weak_configs": config.vuln_check_weak_configs,
            "check_software": config.vuln_check_software,
        })
    return _vuln_scanner


def get_email_analyzer():
    """Get the Email Analyzer module singleton."""
    global _email_analyzer
    if _email_analyzer is None:
        from .modules.email_analyzer import EmailAnalyzer
        _email_analyzer = EmailAnalyzer()
    return _email_analyzer


def get_threat_intelligence():
    """Get the Threat Intelligence module singleton."""
    global _threat_intelligence
    if _threat_intelligence is None:
        from .modules.threat_intelligence import ThreatIntelligence
        config = get_app_config()
        _threat_intelligence = ThreatIntelligence(config={
            "feed_max_events": config.threat_feed_max_events,
            "correlation_window": config.threat_correlation_window,
        })
    return _threat_intelligence


def get_anomaly_detector():
    """Get the Anomaly Detector AI singleton."""
    global _anomaly_detector
    if _anomaly_detector is None:
        from .ai.anomaly_detector import AnomalyDetector
        config = get_app_config()
        _anomaly_detector = AnomalyDetector(
            model_dir=config.ai_model_dir,
            threshold=config.ai_anomaly_threshold,
        )
    return _anomaly_detector


def get_nlp_analyzer():
    """Get the NLP Analyzer AI singleton."""
    global _nlp_analyzer
    if _nlp_analyzer is None:
        from .ai.nlp_analyzer import NLPAnalyzer
        _nlp_analyzer = NLPAnalyzer()
    return _nlp_analyzer


def get_threat_correlator():
    """Get the Threat Correlator AI singleton."""
    global _threat_correlator
    if _threat_correlator is None:
        from .ai.threat_correlator import ThreatCorrelator
        config = get_app_config()
        _threat_correlator = ThreatCorrelator(
            max_events=config.threat_feed_max_events,
            max_age_hours=config.threat_correlation_window,
        )
    return _threat_correlator
