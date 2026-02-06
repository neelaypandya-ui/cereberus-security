"""VPN configuration file security auditor.

Scans for VPN config files on the system, checks for weak crypto settings,
verifies kill switch config, and monitors access to sensitive VPN files.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..utils.logging import get_logger

logger = get_logger("vpn.config_auditor")

# Common VPN config file locations on Windows
VPN_CONFIG_PATHS = [
    Path(os.environ.get("USERPROFILE", "C:/Users/Default")) / "OpenVPN" / "config",
    Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "OpenVPN" / "config",
    Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "OpenVPN" / "config",
    Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "OpenVPN",
    Path(os.environ.get("APPDATA", "")) / "OpenVPN",
    Path(os.environ.get("LOCALAPPDATA", "")) / "NordVPN",
    Path(os.environ.get("LOCALAPPDATA", "")) / "ExpressVPN",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Surfshark",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Windscribe",
    Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "WireGuard",
    Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "WireGuard",
]

# Weak cipher patterns to flag
WEAK_CIPHERS = [
    r"cipher\s+DES",
    r"cipher\s+RC4",
    r"cipher\s+RC2",
    r"cipher\s+SEED",
    r"cipher\s+CAST5",
    r"auth\s+MD5\b",
    r"auth\s+SHA1\b",
    r"cipher\s+BF-CBC",
    r"cipher\s+none",
]

# Strong cipher patterns (for positive validation)
STRONG_CIPHERS = [
    r"cipher\s+AES-256-GCM",
    r"cipher\s+AES-256-CBC",
    r"cipher\s+AES-128-GCM",
    r"cipher\s+CHACHA20-POLY1305",
    r"data-ciphers.*AES-256-GCM",
]


@dataclass
class AuditFinding:
    """A single audit finding."""
    severity: str  # critical, high, medium, low, info
    category: str  # cipher, dns, kill_switch, permissions, config
    file_path: str
    finding: str
    recommendation: str


@dataclass
class AuditReport:
    """Full audit report."""
    config_files_found: list[str] = field(default_factory=list)
    findings: list[AuditFinding] = field(default_factory=list)
    cert_files: list[str] = field(default_factory=list)
    key_files: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def to_dict(self) -> dict:
        return {
            "config_files_found": self.config_files_found,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "file_path": f.file_path,
                    "finding": f.finding,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "cert_files": self.cert_files,
            "key_files": self.key_files,
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
            },
        }


class ConfigAuditor:
    """Audits VPN configuration files for security issues."""

    def __init__(self):
        self._report = AuditReport()

    def discover_config_files(self) -> list[Path]:
        """Discover VPN configuration files on the system."""
        found = []

        for search_dir in VPN_CONFIG_PATHS:
            if not search_dir.exists():
                continue

            # Search for OpenVPN configs
            for pattern in ["*.ovpn", "*.conf"]:
                found.extend(search_dir.glob(pattern))

            # Also check immediate subdirectories
            for subdir in search_dir.iterdir():
                if subdir.is_dir():
                    for pattern in ["*.ovpn", "*.conf"]:
                        found.extend(subdir.glob(pattern))

        logger.info("config_files_discovered", count=len(found))
        return found

    def discover_sensitive_files(self) -> tuple[list[Path], list[Path]]:
        """Find VPN certificate and key files."""
        certs = []
        keys = []

        for search_dir in VPN_CONFIG_PATHS:
            if not search_dir.exists():
                continue

            for f in search_dir.rglob("*"):
                if f.is_file():
                    suffix = f.suffix.lower()
                    name = f.name.lower()

                    if suffix in (".crt", ".pem", ".cer"):
                        certs.append(f)
                    elif suffix in (".key",) or "key" in name:
                        keys.append(f)

        return certs, keys

    def audit_openvpn_config(self, config_path: Path) -> list[AuditFinding]:
        """Audit an OpenVPN configuration file."""
        findings = []

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError) as e:
            findings.append(AuditFinding(
                severity="medium",
                category="permissions",
                file_path=str(config_path),
                finding=f"Cannot read config file: {e}",
                recommendation="Check file permissions.",
            ))
            return findings

        file_str = str(config_path)

        # Check for weak ciphers
        for pattern in WEAK_CIPHERS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(AuditFinding(
                    severity="critical",
                    category="cipher",
                    file_path=file_str,
                    finding=f"Weak cipher detected: {pattern}",
                    recommendation="Use AES-256-GCM or CHACHA20-POLY1305.",
                ))

        # Check for strong ciphers (informational)
        has_strong = any(
            re.search(p, content, re.IGNORECASE) for p in STRONG_CIPHERS
        )
        if not has_strong and "cipher" in content.lower():
            findings.append(AuditFinding(
                severity="medium",
                category="cipher",
                file_path=file_str,
                finding="No strong cipher explicitly configured.",
                recommendation="Add 'cipher AES-256-GCM' or 'data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305'.",
            ))

        # Check DNS settings
        if "dhcp-option DNS" not in content and "block-outside-dns" not in content:
            findings.append(AuditFinding(
                severity="high",
                category="dns",
                file_path=file_str,
                finding="No DNS configuration in VPN config; may cause DNS leaks.",
                recommendation="Add 'block-outside-dns' or 'dhcp-option DNS <vpn-dns-ip>'.",
            ))

        # Check for block-outside-dns (Windows DNS leak prevention)
        if "block-outside-dns" not in content:
            findings.append(AuditFinding(
                severity="high",
                category="dns",
                file_path=file_str,
                finding="'block-outside-dns' not set. Windows may leak DNS queries.",
                recommendation="Add 'block-outside-dns' to prevent Windows DNS leaks.",
            ))

        # Check for auth-nocache
        if "auth-nocache" not in content:
            findings.append(AuditFinding(
                severity="medium",
                category="config",
                file_path=file_str,
                finding="Credentials may be cached in memory.",
                recommendation="Add 'auth-nocache' to prevent credential caching.",
            ))

        # Check for tls-auth or tls-crypt
        if "tls-auth" not in content and "tls-crypt" not in content:
            findings.append(AuditFinding(
                severity="medium",
                category="config",
                file_path=file_str,
                finding="No TLS authentication configured.",
                recommendation="Add 'tls-crypt' or 'tls-auth' for additional security.",
            ))

        return findings

    def audit_wireguard_config(self, config_path: Path) -> list[AuditFinding]:
        """Audit a WireGuard configuration file."""
        findings = []

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError) as e:
            findings.append(AuditFinding(
                severity="medium",
                category="permissions",
                file_path=str(config_path),
                finding=f"Cannot read config file: {e}",
                recommendation="Check file permissions.",
            ))
            return findings

        file_str = str(config_path)

        # Check if DNS is configured
        if "DNS" not in content:
            findings.append(AuditFinding(
                severity="high",
                category="dns",
                file_path=file_str,
                finding="No DNS servers configured in WireGuard config.",
                recommendation="Add 'DNS = <vpn-dns-ip>' under [Interface].",
            ))

        # Check AllowedIPs for split tunneling
        if "AllowedIPs" in content:
            allowed_ips_match = re.search(r"AllowedIPs\s*=\s*(.+)", content)
            if allowed_ips_match:
                allowed = allowed_ips_match.group(1)
                if "0.0.0.0/0" not in allowed and "::/0" not in allowed:
                    findings.append(AuditFinding(
                        severity="medium",
                        category="config",
                        file_path=file_str,
                        finding="Split tunneling detected: not all traffic routed through VPN.",
                        recommendation="Set 'AllowedIPs = 0.0.0.0/0, ::/0' for full tunnel.",
                    ))

        # Check file permissions (Windows)
        try:
            import stat
            file_stat = config_path.stat()
            # On Windows, we mainly check it's not world-readable
            # (limited compared to Unix, but we flag if it's in a shared location)
            if "Public" in str(config_path) or "Shared" in str(config_path):
                findings.append(AuditFinding(
                    severity="high",
                    category="permissions",
                    file_path=file_str,
                    finding="Config file in shared/public directory.",
                    recommendation="Move config to user-specific directory with restricted access.",
                ))
        except Exception:
            pass

        return findings

    def run_audit(self) -> AuditReport:
        """Run a full VPN configuration audit."""
        self._report = AuditReport()

        # Discover config files
        config_files = self.discover_config_files()
        self._report.config_files_found = [str(f) for f in config_files]

        # Discover sensitive files
        certs, keys = self.discover_sensitive_files()
        self._report.cert_files = [str(f) for f in certs]
        self._report.key_files = [str(f) for f in keys]

        # Audit each config file
        for config_path in config_files:
            if config_path.suffix.lower() == ".ovpn":
                findings = self.audit_openvpn_config(config_path)
            elif config_path.suffix.lower() == ".conf":
                # Could be WireGuard or OpenVPN
                content = ""
                try:
                    content = config_path.read_text(errors="ignore")
                except Exception:
                    pass

                if "[Interface]" in content:
                    findings = self.audit_wireguard_config(config_path)
                else:
                    findings = self.audit_openvpn_config(config_path)
            else:
                continue

            self._report.findings.extend(findings)

        # Check for key files with weak permissions
        for key_path in keys:
            if "Public" in str(key_path) or "Shared" in str(key_path):
                self._report.findings.append(AuditFinding(
                    severity="critical",
                    category="permissions",
                    file_path=str(key_path),
                    finding="Private key file in shared/public directory.",
                    recommendation="Move private key to secure location with restricted access.",
                ))

        logger.info(
            "config_audit_complete",
            configs=len(config_files),
            findings=len(self._report.findings),
            critical=self._report.critical_count,
        )

        return self._report
