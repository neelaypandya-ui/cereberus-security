"""Email Analyzer Module — on-demand phishing/threat content analysis.

Delegates to the NLP Analyzer AI layer for text and URL analysis.
Keeps a history of recent analyses in memory.
"""

from collections import deque
from datetime import datetime, timezone

from .base_module import BaseModule


class EmailAnalyzer(BaseModule):
    """Analyzes email/text content for phishing and threats on demand."""

    def __init__(self, config: dict | None = None):
        super().__init__(name="email_analyzer", config=config)
        self._nlp_analyzer = None
        self._recent_analyses: deque[dict] = deque(maxlen=100)
        self._ioc_matcher = None

    async def start(self) -> None:
        self.running = True
        self.health_status = "running"
        self._ensure_nlp()
        self.logger.info("email_analyzer_started")

    async def stop(self) -> None:
        self.running = False
        self.health_status = "stopped"
        self.logger.info("email_analyzer_stopped")

    async def health_check(self) -> dict:
        self.heartbeat()
        return {
            "status": self.health_status,
            "details": {
                "total_analyses": len(self._recent_analyses),
            },
        }

    def _ensure_nlp(self):
        """Lazy-load the NLP analyzer."""
        if self._nlp_analyzer is None:
            from ..ai.nlp_analyzer import NLPAnalyzer
            self._nlp_analyzer = NLPAnalyzer()

    def analyze_content(self, text: str, urls: list[str] | None = None) -> dict:
        """Analyze text content (email body, message, etc.) for threats.

        Args:
            text: The text content to analyze.
            urls: Optional list of URLs found in the content.

        Returns:
            Analysis result dict with threat_score, verdict, indicators.
        """
        self._ensure_nlp()

        result = self._nlp_analyzer.analyze_content(text, urls)

        analysis = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "text_preview": text[:200] + "..." if len(text) > 200 else text,
            "url_count": len(urls) if urls else 0,
            **result,
        }

        # Check URLs against IOC database
        if self._ioc_matcher and urls:
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                ioc_matches = loop.run_until_complete(self._ioc_matcher.check_urls(urls))
                if ioc_matches:
                    analysis["ioc_matches"] = ioc_matches
                    analysis["threat_score"] = min(1.0, analysis.get("threat_score", 0) + 0.3)
            except RuntimeError:
                pass
            except Exception:
                pass

        self._recent_analyses.appendleft(analysis)
        self.heartbeat()

        return analysis

    def set_ioc_matcher(self, matcher) -> None:
        """Attach an IOCMatcher for URL checking during analysis."""
        self._ioc_matcher = matcher
        self.logger.info("ioc_matcher_attached")

    def get_recent_analyses(self, limit: int = 50) -> list[dict]:
        """Get recent analysis results."""
        return list(self._recent_analyses)[:limit]
