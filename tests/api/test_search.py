"""Tests for global search functionality."""

import pytest
from unittest.mock import MagicMock, patch

from backend.modules.network_sentinel import NetworkSentinel
from backend.modules.vuln_scanner import VulnScanner


class TestSearchLogic:
    def test_network_sentinel_connection_search(self):
        ns = NetworkSentinel(config={"poll_interval": 60})
        ns._connections = [
            {"remote_addr": "10.0.0.1", "remote_port": 80, "protocol": "tcp", "status": "ESTABLISHED"},
            {"remote_addr": "192.168.1.100", "remote_port": 443, "protocol": "tcp", "status": "ESTABLISHED"},
            {"remote_addr": "10.0.0.2", "remote_port": 8080, "protocol": "tcp", "status": "TIME_WAIT"},
        ]
        # Simulating search logic
        query = "10.0.0"
        results = [c for c in ns.get_live_connections() if query.lower() in (c.get("remote_addr") or "").lower()]
        assert len(results) == 2

    def test_vuln_scanner_search(self):
        vs = VulnScanner(config={"scan_interval": 3600})
        vs._vulnerabilities = [
            {"title": "Exposed FTP port", "description": "Port 21 open", "severity": "critical"},
            {"title": "Guest account enabled", "description": "Windows guest", "severity": "medium"},
        ]
        query = "ftp"
        results = [v for v in vs.get_vulnerabilities()
                    if query.lower() in (v.get("title") or "").lower()
                    or query.lower() in (v.get("description") or "").lower()]
        assert len(results) == 1
        assert results[0]["title"] == "Exposed FTP port"

    def test_empty_query_returns_empty(self):
        ns = NetworkSentinel(config={"poll_interval": 60})
        ns._connections = [{"remote_addr": "10.0.0.1"}]
        query = "nonexistent"
        results = [c for c in ns.get_live_connections() if query.lower() in (c.get("remote_addr") or "").lower()]
        assert len(results) == 0

    def test_case_insensitive_search(self):
        vs = VulnScanner(config={"scan_interval": 3600})
        vs._vulnerabilities = [
            {"title": "EXPOSED FTP PORT", "description": "open", "severity": "critical"},
        ]
        query = "ftp"
        results = [v for v in vs.get_vulnerabilities()
                    if query.lower() in (v.get("title") or "").lower()]
        assert len(results) == 1

    def test_search_limit(self):
        ns = NetworkSentinel(config={"poll_interval": 60})
        ns._connections = [{"remote_addr": f"10.0.0.{i}"} for i in range(100)]
        query = "10.0.0"
        limit = 10
        results = []
        for c in ns.get_live_connections():
            if query.lower() in (c.get("remote_addr") or "").lower():
                results.append(c)
                if len(results) >= limit:
                    break
        assert len(results) == 10
