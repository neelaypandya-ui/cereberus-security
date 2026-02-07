"""Tests for the Email Analyzer module."""

import pytest

from backend.modules.email_analyzer import EmailAnalyzer


class TestEmailAnalyzer:
    @pytest.fixture
    def analyzer(self):
        ea = EmailAnalyzer()
        return ea

    def test_analyze_clean_content(self, analyzer):
        result = analyzer.analyze_content("Hey, here's the meeting agenda for tomorrow.")
        assert result["verdict"] == "clean"
        assert result["threat_score"] < 0.3
        assert "timestamp" in result

    def test_analyze_phishing_content(self, analyzer):
        text = (
            "URGENT: Your account has been suspended. "
            "Enter your password immediately to confirm your account. "
            "Failure to act within 24 hours will result in permanent closure."
        )
        result = analyzer.analyze_content(text)
        assert result["verdict"] in ("suspicious", "phishing")
        assert result["threat_score"] > 0.3
        assert len(result["indicators"]) > 0

    def test_analyze_with_urls(self, analyzer):
        text = "Click here to verify your account."
        urls = ["http://192.168.1.1/login", "http://evil.xyz/verify"]
        result = analyzer.analyze_content(text, urls)
        assert result["url_count"] == 2
        assert result["threat_score"] > 0

    def test_text_preview_truncation(self, analyzer):
        long_text = "A" * 500
        result = analyzer.analyze_content(long_text)
        assert len(result["text_preview"]) < 210  # 200 + "..."

    def test_recent_analyses_storage(self, analyzer):
        for i in range(5):
            analyzer.analyze_content(f"Test email {i}")

        recent = analyzer.get_recent_analyses()
        assert len(recent) == 5
        # Most recent first
        assert "Test email 4" in recent[0]["text_preview"]

    def test_recent_analyses_limit(self, analyzer):
        for i in range(10):
            analyzer.analyze_content(f"Test email {i}")

        recent = analyzer.get_recent_analyses(limit=3)
        assert len(recent) == 3

    def test_recent_analyses_max_100(self, analyzer):
        for i in range(110):
            analyzer.analyze_content(f"Email {i}")

        recent = analyzer.get_recent_analyses(limit=200)
        assert len(recent) == 100  # deque maxlen is 100

    @pytest.mark.asyncio
    async def test_start_stop(self, analyzer):
        await analyzer.start()
        assert analyzer.running is True
        assert analyzer.health_status == "running"

        await analyzer.stop()
        assert analyzer.running is False

    @pytest.mark.asyncio
    async def test_health_check(self, analyzer):
        health = await analyzer.health_check()
        assert "status" in health
        assert "details" in health
        assert "total_analyses" in health["details"]
