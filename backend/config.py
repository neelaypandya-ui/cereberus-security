"""Cereberus configuration system using Pydantic Settings."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CereberusConfig(BaseSettings):
    """Main configuration class. Loads from .env file and environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    app_name: str = "CEREBERUS"
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = 8000

    # Database
    database_url: str = "sqlite+aiosqlite:///./cereberus.db"

    # Auth
    secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60
    min_password_length: int = 12

    # Cookie
    cookie_secure: bool = True

    # CORS
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Logging
    log_dir: str = "logs"
    log_max_bytes: int = 10_000_000
    log_backup_count: int = 5

    # VPN
    vpn_kill_switch_mode: str = "alert_only"  # full / app_specific / alert_only
    vpn_leak_check_interval: int = 60
    vpn_trusted_interfaces: list[str] = []
    vpn_trusted_dns: list[str] = []

    # Modules
    module_network_sentinel: bool = True
    module_brute_force_shield: bool = True
    module_file_integrity: bool = True
    module_process_analyzer: bool = True
    module_vuln_scanner: bool = True
    module_threat_intelligence: bool = True

    # Network Sentinel
    network_poll_interval: int = 5  # seconds between scans
    network_suspicious_ports: list[int] = [
        4444, 5555, 1337, 31337, 6666, 6667, 12345, 27374,
        1234, 3127, 3128, 4443, 8443,
    ]

    # File Integrity
    file_integrity_scan_interval: int = 300  # seconds between auto-scans
    file_integrity_watched_paths: list[str] = [
        r"C:\Windows\System32\drivers\etc",  # hosts file, network config
        r"C:\Windows\System32\config",        # SAM, SECURITY, SYSTEM hives
    ]
    file_integrity_exclusion_patterns: list[str] = [
        "*.tmp", "*.log", "*.pyc", "__pycache__", "*.pyo",
        ".git", "*.swp", "*.swo", "node_modules",
    ]
    file_integrity_max_file_size: int = 50_000_000  # 50 MB

    # Brute Force Shield
    brute_force_poll_interval: int = 10  # seconds between event log reads
    brute_force_threshold: int = 5  # failed attempts before block
    brute_force_window_seconds: int = 300  # sliding window size
    brute_force_block_duration: int = 3600  # auto-unblock after N seconds
    brute_force_whitelist_ips: list[str] = ["127.0.0.1", "::1"]

    # Process Analyzer
    process_poll_interval: int = 10  # seconds between process scans
    process_suspicious_names: list[str] = [
        "mimikatz", "lazagne", "procdump", "sharphound", "bloodhound",
        "cobaltstrike", "beacon", "meterpreter", "netcat", "ncat",
        "psexec", "wce", "pwdump", "fgdump", "gsecdump",
    ]

    # Vulnerability Scanner
    vuln_scan_interval: int = 3600  # seconds between auto-scans
    vuln_check_windows_updates: bool = True
    vuln_check_open_ports: bool = True
    vuln_check_weak_configs: bool = True
    vuln_check_software: bool = True

    # Resource Monitor
    module_resource_monitor: bool = True
    resource_poll_interval: int = 10
    resource_cpu_threshold: float = 90.0
    resource_memory_threshold: float = 85.0
    resource_disk_threshold: float = 90.0

    # Persistence Scanner
    module_persistence_scanner: bool = True
    persistence_scan_interval: int = 600

    # Event Log Monitor (Phase 11)
    module_event_log_monitor: bool = True
    event_log_poll_interval: int = 15
    event_log_max_events: int = 500
    event_log_enable_sysmon: bool = True
    event_log_max_per_query: int = 50

    # Ransomware Detector (Phase 12)
    module_ransomware_detector: bool = True
    ransomware_poll_interval: int = 10
    ransomware_canary_content: str = "CEREBERUS_CANARY_DO_NOT_MODIFY"

    # Commander Bond (Phase 12)
    module_commander_bond: bool = True
    bond_scan_interval: int = 21600  # 6 hours

    # YARA Scanner (Phase 15)
    yara_rules_dir: str = "yara_rules"
    yara_scan_timeout: int = 120
    yara_max_file_size: int = 100_000_000  # 100 MB
    yara_auto_scan_on_integrity: bool = True

    # Memory Scanner (Phase 15)
    module_memory_scanner: bool = True
    memory_scan_interval: int = 300
    memory_scan_max_processes: int = 200
    memory_rwx_alert_threshold: int = 3

    # Event Bus / EvtSubscribe (Phase 15)
    event_log_use_evt_subscribe: bool = True
    event_log_expanded_sysmon: bool = True
    event_bus_queue_size: int = 10000

    # Sword Protocol (Phase 15)
    sword_protocol_enabled: bool = True
    sword_max_rate: int = 20
    sword_rate_window: int = 300

    # Overwatch Protocol (Phase 15)
    overwatch_check_interval: int = 600
    overwatch_backup_on_tamper: bool = True

    # Database Performance (Phase 13)
    db_wal_mode: bool = True
    db_busy_timeout: int = 5000
    db_synchronous: str = "NORMAL"

    # WebSocket (Phase 13)
    ws_max_connections: int = 100
    ws_queue_size: int = 50
    ws_heartbeat_interval: int = 30

    # Infrastructure (Phase 13)
    shutdown_timeout_seconds: int = 15
    health_monitor_interval: int = 60
    task_max_restarts: int = 3

    # Phase 13: Configurable Detection Thresholds
    # IOC
    ioc_cache_ttl: int = 300  # seconds
    ioc_cache_max_size: int = 10000

    # Detection thresholds
    exfil_bytes_threshold: int = 10_000_000  # 10 MB
    anomaly_cooldown_minutes: int = 30

    # VirusTotal severity thresholds
    vt_severity_critical_threshold: int = 10
    vt_severity_high_threshold: int = 5
    vt_severity_medium_threshold: int = 2
    vt_severity_low_threshold: int = 1

    # AbuseIPDB thresholds
    abuse_critical_threshold: int = 80
    abuse_high_threshold: int = 50
    abuse_medium_threshold: int = 25

    # Commander Bond feed limits
    bond_cisa_limit: int = 30
    bond_nvd_limit: int = 20
    bond_urlhaus_limit: int = 20
    bond_feodo_limit: int = 20
    bond_threatfox_limit: int = 15

    # Correlation windows
    correlation_window_minutes: int = 60
    correlation_min_events: int = 2

    # C2 Beaconing Detection (Phase 12)
    beacon_min_connections: int = 10
    beacon_interval_tolerance: float = 0.15
    beacon_analysis_window: int = 600

    # Threat Intelligence
    threat_feed_max_events: int = 1000
    threat_correlation_window: float = 1.0  # hours

    # AI
    ai_anomaly_threshold: float = 2.0
    ai_model_dir: str = "models"
    ai_baseline_learning_hours: int = 24
    ai_auto_retrain_interval_hours: int = 24
    ai_drift_threshold: float = 0.3

    # Alerting
    alert_desktop_notifications: bool = False
    alert_webhook_url: Optional[str] = None

    # Phase 7: Incident Response
    incident_auto_create_from_correlation: bool = True
    playbook_execution_enabled: bool = True
    remediation_require_confirmation_for_critical: bool = True
    quarantine_vault_dir: str = "quarantine_vault"

    # Phase 8: External Integrations
    feed_poll_enabled: bool = True
    feed_default_poll_interval: int = 3600
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    notification_dispatch_enabled: bool = True
    export_dir: str = "exports"
    export_max_rows: int = 10000

    # Phase 9: RBAC & Data Lifecycle
    retention_alerts_days: int = 90
    retention_audit_days: int = 365
    retention_anomaly_days: int = 30
    retention_snapshots_days: int = 7
    retention_exports_days: int = 30
    retention_cleanup_interval_hours: int = 24
    retention_incidents_days: int = 365
    retention_remediation_days: int = 180
    retention_comments_days: int = 365
    retention_iocs_days: int = 180

    @model_validator(mode="after")
    def reject_default_secret_key(self):
        if self.secret_key == "CHANGE_ME_IN_PRODUCTION" and not self.debug:
            raise ValueError(
                "INSECURE_SECRET_KEY — default secret_key detected in production mode. "
                "Set a strong, unique SECRET_KEY in .env before deploying."
            )
        return self

    @field_validator("vpn_kill_switch_mode")
    @classmethod
    def validate_kill_switch_mode(cls, v: str) -> str:
        allowed = {"full", "app_specific", "alert_only"}
        if v not in allowed:
            raise ValueError(f"vpn_kill_switch_mode must be one of {allowed}")
        return v

    @property
    def base_dir(self) -> Path:
        return Path(__file__).resolve().parent.parent


def get_config() -> CereberusConfig:
    """Factory function to create config instance."""
    return CereberusConfig()
