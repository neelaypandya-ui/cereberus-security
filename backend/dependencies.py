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
