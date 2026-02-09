"""The Checkpoint — validates all targets before they reach the execution chamber.

Input validation utilities for remediation engine parameters and API route models.
Prevents command injection by rejecting shell metacharacters and enforcing strict formats.
"""

import ipaddress
import re

# Shell metacharacters that must never reach subprocess
_SHELL_META = re.compile(r'[;|&`$<>{}()\n\r]')

# Valid username: alphanumeric, dots, hyphens, underscores; max 64 chars
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,64}$')

# Valid process name: alphanumeric, dots, hyphens, underscores; max 255 chars
_PROCESS_NAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,255}$')

# Valid interface name: no shell metacharacters, max 128 chars
_INTERFACE_RE = re.compile(r'^[a-zA-Z0-9 ._-]{1,128}$')

# Valid firewall rule name: alphanumeric, underscores, hyphens
_RULE_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]{1,200}$')

# Valid protocols
VALID_PROTOCOLS = {"TCP", "UDP", "ANY"}


def validate_ip_address(value: str) -> str:
    """Validate and return a normalized IP address string.

    Raises ValueError if the input is not a valid IPv4 or IPv6 address.
    """
    try:
        addr = ipaddress.ip_address(value.strip())
        return str(addr)
    except ValueError:
        raise ValueError(f"Invalid IP address: {value!r}")


def validate_port(value: int) -> int:
    """Validate a port number is in range 1-65535."""
    if not isinstance(value, int) or value < 1 or value > 65535:
        raise ValueError(f"Port must be an integer between 1 and 65535, got: {value!r}")
    return value


def validate_protocol(value: str) -> str:
    """Validate protocol is TCP, UDP, or ANY."""
    upper = value.strip().upper()
    if upper not in VALID_PROTOCOLS:
        raise ValueError(f"Protocol must be one of {VALID_PROTOCOLS}, got: {value!r}")
    return upper


def validate_username(value: str) -> str:
    """Validate a Windows username (alphanumeric + dots + hyphens + underscores, max 64)."""
    if not _USERNAME_RE.match(value):
        raise ValueError(
            f"Invalid username: must be alphanumeric with dots/hyphens/underscores, "
            f"max 64 chars. Got: {value!r}"
        )
    return value


def validate_interface_name(value: str) -> str:
    """Validate a network interface name (no shell metacharacters, max 128)."""
    if not _INTERFACE_RE.match(value):
        raise ValueError(
            f"Invalid interface name: must be alphanumeric with spaces/dots/hyphens/underscores, "
            f"max 128 chars. Got: {value!r}"
        )
    return value


def validate_process_target(value: str) -> str:
    """Validate a process target — either a PID (integer) or process name.

    PID must be 1-999999. Names must match alphanumeric + dots/hyphens/underscores.
    """
    if value.isdigit():
        pid = int(value)
        if pid < 1 or pid > 999999:
            raise ValueError(f"PID must be between 1 and 999999, got: {pid}")
        return value
    if not _PROCESS_NAME_RE.match(value):
        raise ValueError(
            f"Invalid process name: must be alphanumeric with dots/hyphens/underscores. "
            f"Got: {value!r}"
        )
    return value


def validate_file_path(value: str, allowed_base: str | None = None) -> str:
    """Validate a file path — reject shell metacharacters, traversal, and null bytes."""
    if _SHELL_META.search(value):
        raise ValueError(
            f"File path contains forbidden characters (shell metacharacters): {value!r}"
        )
    if len(value) > 500:
        raise ValueError(f"File path too long (max 500 chars): {len(value)}")
    if ".." in value:
        raise ValueError("Path traversal not allowed")
    if "\x00" in value:
        raise ValueError("Null bytes not allowed in file path")
    if allowed_base:
        from pathlib import Path
        resolved = str(Path(value).resolve())
        base_resolved = str(Path(allowed_base).resolve())
        if not resolved.startswith(base_resolved):
            raise ValueError(f"Path must be within {allowed_base}")
    return value


def sanitize_firewall_rule_name(value: str) -> str:
    """Sanitize a firewall rule name — strip non-alphanumeric except underscores and hyphens."""
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', value)
    if len(sanitized) > 200:
        sanitized = sanitized[:200]
    return sanitized
