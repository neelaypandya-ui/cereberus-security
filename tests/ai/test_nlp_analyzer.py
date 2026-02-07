"""Tests for the AI NLP Analyzer."""

import pytest

from backend.ai.nlp_analyzer import NLPAnalyzer


class TestNLPAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return NLPAnalyzer()

    def test_clean_text(self, analyzer):
        result = analyzer.analyze_text("Hello, this is a normal business email about our meeting tomorrow.")
        assert result["keyword_score"] == 0.0
        assert result["urgency_score"] == 0.0
        assert result["credential_request"] is False
        assert len(result["indicators"]) == 0

    def test_phishing_text(self, analyzer):
        text = (
            "Your account has been suspended due to unauthorized access. "
            "Please verify your password immediately by clicking here. "
            "Failure to act within 24 hours will result in account closure."
        )
        result = analyzer.analyze_text(text)
        assert result["keyword_score"] > 0
        assert result["urgency_score"] > 0
        assert len(result["indicators"]) > 0
        assert any("phishing_keyword" in i for i in result["indicators"])
        assert any("urgency" in i for i in result["indicators"])

    def test_credential_request_detection(self, analyzer):
        text = "Please enter your password to verify your identity."
        result = analyzer.analyze_text(text)
        assert result["credential_request"] is True
        assert "credential_request_detected" in result["indicators"]

    def test_clean_url(self, analyzer):
        result = analyzer.analyze_url("https://www.example.com/page")
        assert result["url_score"] == 0.0
        assert len(result["indicators"]) == 0

    def test_ip_based_url(self, analyzer):
        result = analyzer.analyze_url("http://192.168.1.1/login")
        assert result["url_score"] > 0
        assert "ip_based_url" in result["indicators"]

    def test_suspicious_tld(self, analyzer):
        result = analyzer.analyze_url("http://secure-bank.xyz/verify")
        assert result["url_score"] > 0
        assert any("suspicious_tld" in i for i in result["indicators"])

    def test_url_shortener(self, analyzer):
        result = analyzer.analyze_url("https://bit.ly/abc123")
        assert result["url_score"] > 0
        assert "url_shortener" in result["indicators"]

    def test_excessive_subdomains(self, analyzer):
        result = analyzer.analyze_url("http://secure.login.bank.verify.example.com/page")
        assert result["url_score"] > 0
        assert "excessive_subdomains" in result["indicators"]

    def test_at_sign_in_url(self, analyzer):
        result = analyzer.analyze_url("http://example.com@evil.com/login")
        assert result["url_score"] > 0
        assert "at_sign_in_url" in result["indicators"]

    def test_combined_clean(self, analyzer):
        result = analyzer.analyze_content("Normal business email.", ["https://www.company.com"])
        assert result["verdict"] == "clean"
        assert result["threat_score"] < 0.3

    def test_combined_phishing(self, analyzer):
        text = (
            "URGENT: Your account has been suspended. "
            "Enter your password immediately to verify your identity. "
            "Click here to confirm your account."
        )
        urls = ["http://192.168.1.1/login.php", "http://secure-bank.xyz/verify"]
        result = analyzer.analyze_content(text, urls)
        assert result["threat_score"] > 0.3
        assert result["verdict"] in ("suspicious", "phishing")
        assert len(result["indicators"]) > 0

    def test_analyze_urls_empty(self, analyzer):
        result = analyzer.analyze_urls([])
        assert result["max_url_score"] == 0.0

    def test_analyze_urls_multiple(self, analyzer):
        result = analyzer.analyze_urls([
            "https://www.safe.com",
            "http://192.168.1.1/evil",
        ])
        assert result["max_url_score"] > 0
        assert len(result["url_details"]) == 2
