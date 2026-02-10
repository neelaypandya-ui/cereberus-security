"""Security modules package."""

from .base_module import BaseModule
from .vpn_guardian import VPNGuardian
from .network_sentinel import NetworkSentinel
from .brute_force_shield import BruteForceShield
from .file_integrity import FileIntegrity
from .process_analyzer import ProcessAnalyzer
from .vuln_scanner import VulnScanner
from .threat_intelligence import ThreatIntelligence

__all__ = [
    "BaseModule",
    "VPNGuardian",
    "NetworkSentinel",
    "BruteForceShield",
    "FileIntegrity",
    "ProcessAnalyzer",
    "VulnScanner",
    "ThreatIntelligence",
]
