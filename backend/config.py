"""Cereberus configuration system using Pydantic Settings."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import field_validator
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

    # Redis
    redis_url: str = "redis://localhost:6379"

    # VPN
    vpn_kill_switch_mode: str = "alert_only"  # full / app_specific / alert_only
    vpn_leak_check_interval: int = 60
    vpn_trusted_interfaces: list[str] = []
    vpn_trusted_dns: list[str] = []

    # Modules
    module_network_sentinel: bool = True
    module_brute_force_shield: bool = True
    module_email_analyzer: bool = True
    module_file_integrity: bool = True
    module_process_analyzer: bool = True
    module_vuln_scanner: bool = True
    module_threat_intelligence: bool = True

    # Network Sentinel
    network_poll_interval: int = 5  # seconds between scans
    network_suspicious_ports: list[int] = [
        4444, 5555, 1337, 31337, 6666, 6667, 12345, 27374,
        1234, 3127, 3128, 8080, 9090, 4443, 8443,
    ]

    # File Integrity
    file_integrity_scan_interval: int = 300  # seconds between auto-scans
    file_integrity_watched_paths: list[str] = []
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

    # Alerting
    alert_desktop_notifications: bool = True
    alert_webhook_url: Optional[str] = None

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
