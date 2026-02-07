"""Tests for report generation."""

import pytest

from backend.utils.report_template import render_report


class TestReportTemplate:
    def test_render_empty_report(self):
        html = render_report({})
        assert "CEREBERUS" in html
        assert "SECURITY ASSESSMENT REPORT" in html
        assert "<!DOCTYPE html>" in html

    def test_render_with_threat_level(self):
        html = render_report({"threat_level": "critical"})
        assert "CRITICAL" in html.upper()

    def test_render_with_alerts(self):
        html = render_report({
            "alerts": [
                {"severity": "high", "title": "Test Alert", "module_source": "test", "timestamp": "2024-01-01T00:00:00"},
            ],
        })
        assert "Test Alert" in html

    def test_render_with_recommendations(self):
        html = render_report({
            "recommendations": ["Update your system", "Check firewall"],
        })
        assert "Update your system" in html
        assert "Check firewall" in html
