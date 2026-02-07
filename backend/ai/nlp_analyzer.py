"""NLP Analyzer — rule-based phishing and threat content analysis.

Uses keyword scoring, URL analysis, and pattern matching to detect
phishing attempts, credential harvesting, and social engineering.
"""

import re
from urllib.parse import urlparse

from ..utils.logging import get_logger

logger = get_logger("ai.nlp_analyzer")

# Phishing keywords with weights
PHISHING_KEYWORDS = {
    "password": 0.3, "credential": 0.3, "verify": 0.2, "account": 0.2,
    "suspended": 0.4, "unauthorized": 0.3, "confirm": 0.2, "expire": 0.3,
    "login": 0.2, "click here": 0.3, "update your": 0.3, "ssn": 0.5,
    "social security": 0.5, "bank account": 0.4, "credit card": 0.4,
    "wire transfer": 0.5, "bitcoin": 0.3, "cryptocurrency": 0.3,
}

# Urgency phrases
URGENCY_PHRASES = {
    "immediately": 0.3, "urgent": 0.4, "act now": 0.4, "limited time": 0.3,
    "within 24 hours": 0.4, "account will be": 0.3, "failure to": 0.3,
    "final warning": 0.4, "last chance": 0.3, "don't delay": 0.3,
    "right away": 0.2, "as soon as possible": 0.2, "asap": 0.2,
}

# Credential request patterns
CREDENTIAL_PATTERNS = [
    re.compile(r"enter\s+(?:your\s+)?(?:password|credentials?|pin|ssn)", re.I),
    re.compile(r"(?:confirm|verify|update)\s+(?:your\s+)?(?:account|identity|information)", re.I),
    re.compile(r"(?:send|provide|share)\s+(?:your\s+)?(?:password|login|credentials?)", re.I),
    re.compile(r"reset\s+(?:your\s+)?password", re.I),
]

# Suspicious TLDs
SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work", ".click", ".loan", ".racing"}

# URL shortener domains
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rb.gy"}

# Homoglyph substitutions (common look-alikes)
HOMOGLYPHS = {
    "0": "o", "1": "l", "vv": "w", "rn": "m",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",  # Cyrillic
}


class NLPAnalyzer:
    """Rule-based NLP threat analysis engine."""

    def __init__(self):
        self.initialized = False

    async def initialize(self) -> None:
        self.initialized = True

    def analyze_text(self, text: str) -> dict:
        """Analyze text content for phishing indicators.

        Returns:
            Dict with keyword_score, urgency_score, credential_request, indicators list.
        """
        text_lower = text.lower()
        indicators = []

        # Keyword scoring
        keyword_score = 0.0
        for keyword, weight in PHISHING_KEYWORDS.items():
            if keyword in text_lower:
                keyword_score += weight
                indicators.append(f"phishing_keyword:{keyword}")

        keyword_score = min(keyword_score, 1.0)

        # Urgency scoring
        urgency_score = 0.0
        for phrase, weight in URGENCY_PHRASES.items():
            if phrase in text_lower:
                urgency_score += weight
                indicators.append(f"urgency:{phrase}")

        urgency_score = min(urgency_score, 1.0)

        # Credential request detection
        credential_request = False
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.search(text):
                credential_request = True
                indicators.append("credential_request_detected")
                break

        return {
            "keyword_score": keyword_score,
            "urgency_score": urgency_score,
            "credential_request": credential_request,
            "indicators": indicators,
        }

    def analyze_url(self, url: str) -> dict:
        """Analyze a single URL for suspicious characteristics.

        Returns:
            Dict with url_score, indicators list.
        """
        indicators = []
        score = 0.0

        try:
            parsed = urlparse(url)
        except Exception:
            return {"url_score": 0.0, "indicators": ["invalid_url"]}

        hostname = parsed.hostname or ""
        path = parsed.path or ""

        # IP-based URL
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            score += 0.4
            indicators.append("ip_based_url")

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                score += 0.3
                indicators.append(f"suspicious_tld:{tld}")
                break

        # URL shortener
        if hostname in URL_SHORTENERS:
            score += 0.2
            indicators.append("url_shortener")

        # Excessive subdomains (more than 3 dots)
        if hostname.count(".") > 3:
            score += 0.2
            indicators.append("excessive_subdomains")

        # Homoglyph detection in hostname
        for fake, real in HOMOGLYPHS.items():
            if fake in hostname:
                score += 0.4
                indicators.append(f"homoglyph:{fake}->{real}")
                break

        # Long path with encoded characters
        if len(path) > 200 or path.count("%") > 5:
            score += 0.1
            indicators.append("obfuscated_path")

        # @ in URL (credential harvesting trick)
        if "@" in url:
            score += 0.4
            indicators.append("at_sign_in_url")

        return {
            "url_score": min(score, 1.0),
            "indicators": indicators,
        }

    def analyze_urls(self, urls: list[str]) -> dict:
        """Analyze multiple URLs, return aggregate score."""
        if not urls:
            return {"max_url_score": 0.0, "url_indicators": [], "url_details": []}

        details = [self.analyze_url(u) for u in urls]
        all_indicators = []
        for d in details:
            all_indicators.extend(d["indicators"])

        max_score = max(d["url_score"] for d in details)

        return {
            "max_url_score": max_score,
            "url_indicators": all_indicators,
            "url_details": details,
        }

    def analyze_content(self, text: str, urls: list[str] | None = None) -> dict:
        """Combined analysis of text content and URLs.

        Returns:
            Dict with threat_score (0-1), indicators, verdict, component scores.
        """
        text_result = self.analyze_text(text)
        url_result = self.analyze_urls(urls or [])

        # Combined threat score (weighted)
        text_score = (
            text_result["keyword_score"] * 0.35 +
            text_result["urgency_score"] * 0.25 +
            (0.3 if text_result["credential_request"] else 0.0)
        )
        url_score = url_result["max_url_score"] * 0.4

        threat_score = min(text_score + url_score, 1.0)

        # Determine verdict
        if threat_score >= 0.6:
            verdict = "phishing"
        elif threat_score >= 0.3:
            verdict = "suspicious"
        else:
            verdict = "clean"

        all_indicators = text_result["indicators"] + url_result["url_indicators"]

        return {
            "threat_score": round(threat_score, 3),
            "verdict": verdict,
            "indicators": all_indicators,
            "text_analysis": text_result,
            "url_analysis": url_result,
        }
