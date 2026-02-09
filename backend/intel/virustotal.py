"""VirusTotal threat intelligence provider."""

import asyncio
import base64
import time
from typing import Optional

import httpx

from ..utils.logging import get_logger

logger = get_logger("intel.virustotal")

_VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalProvider:
    """VirusTotal API v3 provider for hash, IP, and URL lookups."""

    def __init__(self, api_key: Optional[str] = None, config=None) -> None:
        self.api_key = api_key
        self._config = config
        # Rate limit: 4 requests per minute for free-tier
        self._rate_limit_interval = 15.0  # seconds between requests (60/4)
        self._last_request_time: float = 0.0

    async def _rate_limit(self) -> None:
        """Enforce per-minute rate limiting."""
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._rate_limit_interval:
            wait = self._rate_limit_interval - elapsed
            logger.debug("virustotal_rate_limit", wait_seconds=round(wait, 2))
            await asyncio.sleep(wait)
        self._last_request_time = time.monotonic()

    def _headers(self) -> dict:
        """Build request headers with API key."""
        return {"x-apikey": self.api_key or "", "Accept": "application/json"}

    def _severity_from_stats(self, stats: dict) -> str:
        """Derive severity from detection statistics.

        Thresholds are read from config if available, otherwise use defaults.
        """
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = malicious + suspicious

        critical = getattr(self._config, "vt_severity_critical_threshold", 10) if self._config else 10
        high = getattr(self._config, "vt_severity_high_threshold", 5) if self._config else 5
        medium = getattr(self._config, "vt_severity_medium_threshold", 2) if self._config else 2
        low = getattr(self._config, "vt_severity_low_threshold", 1) if self._config else 1

        if total >= critical:
            return "critical"
        if total >= high:
            return "high"
        if total >= medium:
            return "medium"
        if total >= low:
            return "low"
        return "info"

    async def lookup_hash(self, file_hash: str) -> dict:
        """Look up a file hash (MD5, SHA-1, or SHA-256) on VirusTotal.

        Returns normalized IOC format dictionary.
        """
        if not self.api_key:
            logger.warning("virustotal_no_api_key", operation="lookup_hash")
            return {
                "ioc_type": "hash",
                "value": file_hash,
                "severity": "unknown",
                "source": "virustotal",
                "context": {"error": "No API key configured"},
            }

        await self._rate_limit()
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{_VT_BASE_URL}/files/{file_hash}",
                    headers=self._headers(),
                )
                if response.status_code == 404:
                    return {
                        "ioc_type": "hash",
                        "value": file_hash,
                        "severity": "info",
                        "source": "virustotal",
                        "context": {"found": False},
                    }
                response.raise_for_status()
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "ioc_type": "hash",
                    "value": file_hash,
                    "severity": self._severity_from_stats(stats),
                    "source": "virustotal",
                    "context": {
                        "found": True,
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "harmless": stats.get("harmless", 0),
                        "meaningful_name": attrs.get("meaningful_name"),
                        "type_description": attrs.get("type_description"),
                        "reputation": attrs.get("reputation"),
                    },
                }
        except httpx.HTTPStatusError as exc:
            logger.error("virustotal_hash_error", hash=file_hash, status=exc.response.status_code)
            return {
                "ioc_type": "hash",
                "value": file_hash,
                "severity": "unknown",
                "source": "virustotal",
                "context": {"error": f"HTTP {exc.response.status_code}"},
            }
        except Exception as exc:
            logger.error("virustotal_hash_exception", hash=file_hash, error=str(exc))
            return {
                "ioc_type": "hash",
                "value": file_hash,
                "severity": "unknown",
                "source": "virustotal",
                "context": {"error": str(exc)},
            }

    async def lookup_ip(self, ip: str) -> dict:
        """Look up an IP address on VirusTotal.

        Returns normalized IOC format dictionary.
        """
        if not self.api_key:
            logger.warning("virustotal_no_api_key", operation="lookup_ip")
            return {
                "ioc_type": "ip",
                "value": ip,
                "severity": "unknown",
                "source": "virustotal",
                "context": {"error": "No API key configured"},
            }

        await self._rate_limit()
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{_VT_BASE_URL}/ip_addresses/{ip}",
                    headers=self._headers(),
                )
                if response.status_code == 404:
                    return {
                        "ioc_type": "ip",
                        "value": ip,
                        "severity": "info",
                        "source": "virustotal",
                        "context": {"found": False},
                    }
                response.raise_for_status()
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "ioc_type": "ip",
                    "value": ip,
                    "severity": self._severity_from_stats(stats),
                    "source": "virustotal",
                    "context": {
                        "found": True,
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "harmless": stats.get("harmless", 0),
                        "country": attrs.get("country"),
                        "as_owner": attrs.get("as_owner"),
                        "reputation": attrs.get("reputation"),
                        "network": attrs.get("network"),
                    },
                }
        except httpx.HTTPStatusError as exc:
            logger.error("virustotal_ip_error", ip=ip, status=exc.response.status_code)
            return {
                "ioc_type": "ip",
                "value": ip,
                "severity": "unknown",
                "source": "virustotal",
                "context": {"error": f"HTTP {exc.response.status_code}"},
            }
        except Exception as exc:
            logger.error("virustotal_ip_exception", ip=ip, error=str(exc))
            return {
                "ioc_type": "ip",
                "value": ip,
                "severity": "unknown",
                "source": "virustotal",
                "context": {"error": str(exc)},
            }

    async def lookup_url(self, url: str) -> dict:
        """Look up a URL on VirusTotal.

        The URL is base64-encoded (without padding) to form the URL identifier.
        Returns normalized IOC format dictionary.
        """
        if not self.api_key:
            logger.warning("virustotal_no_api_key", operation="lookup_url")
            return {
                "ioc_type": "url",
                "value": url,
                "severity": "unknown",
                "source": "virustotal",
                "context": {"error": "No API key configured"},
            }

        # VirusTotal URL identifier: base64url(url) without trailing '='
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        await self._rate_limit()
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{_VT_BASE_URL}/urls/{url_id}",
                    headers=self._headers(),
                )
                if response.status_code == 404:
                    return {
                        "ioc_type": "url",
                        "value": url,
                        "severity": "info",
                        "source": "virustotal",
                        "context": {"found": False},
                    }
                response.raise_for_status()
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "ioc_type": "url",
                    "value": url,
                    "severity": self._severity_from_stats(stats),
                    "source": "virustotal",
                    "context": {
                        "found": True,
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "harmless": stats.get("harmless", 0),
                        "last_final_url": attrs.get("last_final_url"),
                        "title": attrs.get("title"),
                        "reputation": attrs.get("reputation"),
                    },
                }
        except httpx.HTTPStatusError as exc:
            logger.error("virustotal_url_error", url=url, status=exc.response.status_code)
            return {
                "ioc_type": "url",
                "value": url,
                "severity": "unknown",
                "source": "virustotal",
                "context": {"error": f"HTTP {exc.response.status_code}"},
            }
        except Exception as exc:
            logger.error("virustotal_url_exception", url=url, error=str(exc))
            return {
                "ioc_type": "url",
                "value": url,
                "severity": "unknown",
                "source": "virustotal",
                "context": {"error": str(exc)},
            }
