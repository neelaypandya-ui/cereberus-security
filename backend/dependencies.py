"""FastAPI dependency injection providers."""

import hashlib
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import CereberusConfig, get_config
from .database import get_session, get_session_factory
from .utils.logging import get_logger
from .utils.security import decode_access_token

_dep_logger = get_logger("dependencies")

security_scheme = HTTPBearer(auto_error=False)

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
_resource_monitor = None
_persistence_scanner = None
_anomaly_detector = None
_nlp_analyzer = None
_threat_correlator = None
_isolation_forest_detector = None
_zscore_detector = None
_ensemble_detector = None
_behavioral_baseline = None
_threat_forecaster = None

# Phase 7 engine singletons
_remediation_engine = None
_incident_manager = None
_playbook_executor = None

# Phase 8 integration singletons
_feed_manager = None
_ioc_matcher = None
_notification_dispatcher = None
_data_exporter = None

# Phase 11 singletons
_event_log_monitor = None
_rule_engine = None

# Phase 15 singletons
_yara_scanner = None
_memory_scanner = None
_event_bus = None


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


async def _validate_api_key(api_key: str, config: CereberusConfig) -> Optional[dict]:
    """Validate an API key and return user info if valid."""
    try:
        from .models.api_key import APIKey
        from .models.user import User
        from datetime import datetime, timezone

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        factory = get_session_factory(config)
        async with factory() as session:
            result = await session.execute(
                select(APIKey).where(
                    APIKey.key_hash == key_hash,
                    APIKey.revoked == False,
                )
            )
            api_key_record = result.scalar_one_or_none()
            if api_key_record is None:
                return None

            # Check expiry
            if api_key_record.expires_at and api_key_record.expires_at < datetime.now(timezone.utc):
                return None

            # Update last used
            api_key_record.last_used = datetime.now(timezone.utc)

            # Get user
            user_result = await session.execute(
                select(User).where(User.id == api_key_record.user_id)
            )
            user = user_result.scalar_one_or_none()
            if user is None:
                return None

            await session.commit()

            import json
            permissions = json.loads(api_key_record.permissions_json) if api_key_record.permissions_json else []
            return {
                "sub": user.username,
                "role": user.role,
                "permissions": permissions,
                "auth_method": "api_key",
            }
    except Exception as e:
        _dep_logger.debug("api_key_validation_failed", error=str(e))
        return None


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    config: CereberusConfig = Depends(get_app_config),
) -> dict:
    """Validate JWT token or API key and return current user."""
    # Check X-API-Key header first
    api_key = request.headers.get("X-API-Key")
    if api_key:
        result = await _validate_api_key(api_key, config)
        if result is not None:
            return result
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )

    # Extract token: try httpOnly cookie first, then Bearer header
    raw_token = request.cookies.get("cereberus_session")
    if not raw_token and credentials:
        raw_token = credentials.credentials

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(
        raw_token,
        config.secret_key,
        config.jwt_algorithm,
    )
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check burn list (token revocation) — DB-backed
    from .api.routes.auth import is_token_burned
    from .models.user import User
    factory = get_session_factory(config)
    async with factory() as db:
        if await is_token_burned(raw_token, db):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token revoked \u2014 burn notice active",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Enforce must_change_password — block all endpoints except password change/me/logout
        result = await db.execute(select(User).where(User.username == payload.get("sub")))
        user = result.scalar_one_or_none()
        if user and getattr(user, "must_change_password", False):
            path = request.url.path
            allowed_paths = ("/api/v1/auth/change-password", "/api/v1/auth/me", "/api/v1/auth/logout")
            if not any(path.endswith(p) for p in allowed_paths):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Password change required",
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


def get_resource_monitor():
    """Get the Resource Monitor module singleton."""
    global _resource_monitor
    if _resource_monitor is None:
        from .modules.resource_monitor import ResourceMonitor
        config = get_app_config()
        _resource_monitor = ResourceMonitor(config={
            "poll_interval": config.resource_poll_interval,
            "cpu_threshold": config.resource_cpu_threshold,
            "memory_threshold": config.resource_memory_threshold,
            "disk_threshold": config.resource_disk_threshold,
        })
    return _resource_monitor


def get_persistence_scanner():
    """Get the Persistence Scanner module singleton."""
    global _persistence_scanner
    if _persistence_scanner is None:
        from .modules.persistence_scanner import PersistenceScanner
        config = get_app_config()
        _persistence_scanner = PersistenceScanner(config={
            "scan_interval": config.persistence_scan_interval,
        })
    return _persistence_scanner


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


def get_isolation_forest_detector():
    """Get the Isolation Forest Detector singleton."""
    global _isolation_forest_detector
    if _isolation_forest_detector is None:
        from .ai.isolation_forest_detector import IsolationForestDetector
        config = get_app_config()
        _isolation_forest_detector = IsolationForestDetector(
            model_dir=config.ai_model_dir,
        )
    return _isolation_forest_detector


def get_zscore_detector():
    """Get the Z-Score Detector singleton."""
    global _zscore_detector
    if _zscore_detector is None:
        from .ai.zscore_detector import ZScoreDetector
        config = get_app_config()
        _zscore_detector = ZScoreDetector(
            model_dir=config.ai_model_dir,
        )
    return _zscore_detector


def get_ensemble_detector():
    """Get the Ensemble Detector singleton."""
    global _ensemble_detector
    if _ensemble_detector is None:
        from .ai.ensemble_detector import EnsembleDetector
        config = get_app_config()
        _ensemble_detector = EnsembleDetector(
            autoencoder=get_anomaly_detector(),
            isolation_forest=get_isolation_forest_detector(),
            zscore=get_zscore_detector(),
            weights=config.ai_ensemble_weights,
            consensus_threshold=config.ai_consensus_threshold,
        )
    return _ensemble_detector


def get_behavioral_baseline():
    """Get the Behavioral Baseline Engine singleton."""
    global _behavioral_baseline
    if _behavioral_baseline is None:
        from .ai.behavioral_baseline import BehavioralBaselineEngine
        _behavioral_baseline = BehavioralBaselineEngine()
    return _behavioral_baseline


def get_threat_forecaster():
    """Get the Threat Forecaster singleton."""
    global _threat_forecaster
    if _threat_forecaster is None:
        from .ai.threat_forecaster import ThreatForecaster
        config = get_app_config()
        _threat_forecaster = ThreatForecaster(
            model_dir=config.ai_model_dir,
        )
    return _threat_forecaster


# --- Phase 7: Engine singletons ---

def get_remediation_engine():
    """Get the Remediation Engine singleton."""
    global _remediation_engine
    if _remediation_engine is None:
        from .engine.remediation import RemediationEngine
        config = get_app_config()
        _remediation_engine = RemediationEngine(
            base_dir=config.quarantine_vault_dir,
        )
    return _remediation_engine


def get_incident_manager():
    """Get the Incident Manager singleton."""
    global _incident_manager
    if _incident_manager is None:
        from .engine.incident_manager import IncidentManager
        _incident_manager = IncidentManager()
    return _incident_manager


def get_playbook_executor():
    """Get the Playbook Executor singleton."""
    global _playbook_executor
    if _playbook_executor is None:
        from .engine.playbook_executor import PlaybookExecutor
        _playbook_executor = PlaybookExecutor(
            remediation_engine=get_remediation_engine(),
        )
    return _playbook_executor


# --- Phase 8: Integration singletons ---

def get_feed_manager():
    """Get the Feed Manager singleton."""
    global _feed_manager
    if _feed_manager is None:
        from .intel.feed_manager import FeedManager
        config = get_app_config()
        from .database import get_session_factory
        factory = get_session_factory(config)
        _feed_manager = FeedManager(
            db_session_factory=factory,
            config=config,
        )
    return _feed_manager


def get_ioc_matcher():
    """Get the IOC Matcher singleton."""
    global _ioc_matcher
    if _ioc_matcher is None:
        from .intel.ioc_matcher import IOCMatcher
        config = get_app_config()
        from .database import get_session_factory
        factory = get_session_factory(config)
        _ioc_matcher = IOCMatcher(
            db_session_factory=factory,
            config=config,
        )
    return _ioc_matcher


def get_notification_dispatcher():
    """Get the Notification Dispatcher singleton."""
    global _notification_dispatcher
    if _notification_dispatcher is None:
        from .notifications.dispatcher import NotificationDispatcher
        config = get_app_config()
        from .database import get_session_factory
        factory = get_session_factory(config)
        _notification_dispatcher = NotificationDispatcher(
            db_session_factory=factory,
        )
    return _notification_dispatcher


def get_data_exporter():
    """Get the Data Exporter singleton."""
    global _data_exporter
    if _data_exporter is None:
        from .export.exporter import DataExporter
        config = get_app_config()
        from .database import get_session_factory
        factory = get_session_factory(config)
        _data_exporter = DataExporter(
            db_session_factory=factory,
            export_dir=config.export_dir,
        )
    return _data_exporter


# --- Phase 11: New module singletons ---

def get_event_log_monitor():
    """Get the Event Log Monitor module singleton."""
    global _event_log_monitor
    if _event_log_monitor is None:
        from .modules.event_log_monitor import EventLogMonitor
        config = get_app_config()
        _event_log_monitor = EventLogMonitor(config={
            "poll_interval": getattr(config, "event_log_poll_interval", 15),
            "max_events": getattr(config, "event_log_max_events", 500),
            "enable_sysmon": getattr(config, "event_log_enable_sysmon", True),
            "max_events_per_query": getattr(config, "event_log_max_per_query", 50),
        })
    return _event_log_monitor


def get_rule_engine():
    """Get the Rule Engine singleton."""
    global _rule_engine
    if _rule_engine is None:
        from .ai.rule_engine import RuleEngine
        _rule_engine = RuleEngine()
    return _rule_engine


# --- Phase 12: New module singletons ---

_ransomware_detector = None
_commander_bond = None

def get_ransomware_detector():
    """Get the Ransomware Detector module singleton."""
    global _ransomware_detector
    if _ransomware_detector is None:
        from .modules.ransomware_detector import RansomwareDetector
        config = get_app_config()
        _ransomware_detector = RansomwareDetector(config={
            "poll_interval": config.ransomware_poll_interval,
            "canary_content": config.ransomware_canary_content,
        })
    return _ransomware_detector


def get_commander_bond():
    """Get the Commander Bond module singleton."""
    global _commander_bond
    if _commander_bond is None:
        from .modules.commander_bond import CommanderBond
        config = get_app_config()
        _commander_bond = CommanderBond(config={
            "scan_interval": config.bond_scan_interval,
        })
    return _commander_bond



# --- Disk Sanitation ---

_disk_analyzer = None


def get_disk_analyzer():
    """Get the Disk Analyzer singleton."""
    global _disk_analyzer
    if _disk_analyzer is None:
        from .modules.disk_analyzer import DiskAnalyzer
        _disk_analyzer = DiskAnalyzer()
    return _disk_analyzer


# --- Phase 15 ---

def get_yara_scanner():
    """Get the YARA Scanner singleton."""
    global _yara_scanner
    if _yara_scanner is None:
        from .intel.yara_scanner import YaraScanner
        config = get_app_config()
        import os
        rules_dir = config.yara_rules_dir
        if not os.path.isabs(rules_dir):
            rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), rules_dir)
        _yara_scanner = YaraScanner(
            rules_dir=rules_dir,
            scan_timeout=config.yara_scan_timeout,
            max_file_size=config.yara_max_file_size,
        )
    return _yara_scanner


def get_memory_scanner():
    """Get the Memory Scanner module singleton."""
    global _memory_scanner
    if _memory_scanner is None:
        from .modules.memory_scanner import MemoryScanner
        config = get_app_config()
        _memory_scanner = MemoryScanner(config={
            "scan_interval": config.memory_scan_interval,
            "max_processes": config.memory_scan_max_processes,
            "rwx_alert_threshold": config.memory_rwx_alert_threshold,
        })
    return _memory_scanner


def get_event_bus():
    """Get the EventBus singleton."""
    global _event_bus
    if _event_bus is None:
        from .utils.event_bus import EventBus
        config = get_app_config()
        _event_bus = EventBus(queue_size=config.event_bus_queue_size)
    return _event_bus
