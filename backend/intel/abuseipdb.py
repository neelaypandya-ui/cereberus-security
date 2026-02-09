"""AbuseIPDB threat intelligence provider."""

from typing import Optional

import httpx

from ..utils.logging import get_logger

logger = get_logger("intel.abuseipdb")

_ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com"


class AbuseIPDBProvider:
    """AbuseIPDB API v2 provider for IP reputation checks and blacklist retrieval."""

    def __init__(self, api_key: Optional[str] = None, config=None) -> None:
        self.api_key = api_key
        self._config = config

    def _headers(self) -> dict:
        """Build request headers with API key."""
        return {"Key": self.api_key or "", "Accept": "application/json"}

    def _severity_from_score(self, abuse_confidence_score: int) -> str:
        """Derive severity from AbuseIPDB confidence score (0-100).

        Thresholds are read from config if available, otherwise use defaults.
        """
        critical = getattr(self._config, "abuse_critical_threshold", 80) if self._config else 80
        high = getattr(self._config, "abuse_high_threshold", 50) if self._config else 50
        medium = getattr(self._config, "abuse_medium_threshold", 25) if self._config else 25

        if abuse_confidence_score >= critical:
            return "critical"
        if abuse_confidence_score >= high:
            return "high"
        if abuse_confidence_score >= medium:
            return "medium"
        if abuse_confidence_score > 0:
            return "low"
        return "info"

    async def check_ip(self, ip: str) -> dict:
        """Check an IP address against AbuseIPDB.

        Returns normalized IOC format dictionary.
        """
        if not self.api_key:
            logger.warning("abuseipdb_no_api_key", operation="check_ip")
            return {
                "ioc_type": "ip",
                "value": ip,
                "severity": "unknown",
                "source": "abuseipdb",
                "context": {"error": "No API key configured"},
            }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{_ABUSEIPDB_BASE_URL}/api/v2/check",
                    headers=self._headers(),
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                        "verbose": "",
                    },
                )
                response.raise_for_status()
                data = response.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "ioc_type": "ip",
                    "value": ip,
                    "severity": self._severity_from_score(score),
                    "source": "abuseipdb",
                    "context": {
                        "abuse_confidence_score": score,
                        "country_code": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "total_reports": data.get("totalReports", 0),
                        "num_distinct_users": data.get("numDistinctUsers", 0),
                        "last_reported_at": data.get("lastReportedAt"),
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "usage_type": data.get("usageType"),
                    },
                }
        except httpx.HTTPStatusError as exc:
            logger.error("abuseipdb_check_error", ip=ip, status=exc.response.status_code)
            return {
                "ioc_type": "ip",
                "value": ip,
                "severity": "unknown",
                "source": "abuseipdb",
                "context": {"error": f"HTTP {exc.response.status_code}"},
            }
        except Exception as exc:
            logger.error("abuseipdb_check_exception", ip=ip, error=str(exc))
            return {
                "ioc_type": "ip",
                "value": ip,
                "severity": "unknown",
                "source": "abuseipdb",
                "context": {"error": str(exc)},
            }

    async def get_blacklist(self, limit: int = 100) -> list[dict]:
        """Retrieve the AbuseIPDB blacklist.

        Returns a list of normalized IOC format dictionaries.
        """
        if not self.api_key:
            logger.warning("abuseipdb_no_api_key", operation="get_blacklist")
            return []

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{_ABUSEIPDB_BASE_URL}/api/v2/blacklist",
                    headers=self._headers(),
                    params={"limit": limit, "confidenceMinimum": 90},
                )
                response.raise_for_status()
                data = response.json().get("data", [])

                iocs = []
                for entry in data:
                    ip_address = entry.get("ipAddress", "")
                    score = entry.get("abuseConfidenceScore", 0)
                    iocs.append({
                        "ioc_type": "ip",
                        "value": ip_address,
                        "severity": self._severity_from_score(score),
                        "source": "abuseipdb",
                        "context": {
                            "abuse_confidence_score": score,
                            "country_code": entry.get("countryCode"),
                            "last_reported_at": entry.get("lastReportedAt"),
                        },
                    })
                logger.info("abuseipdb_blacklist_fetched", count=len(iocs))
                return iocs
        except httpx.HTTPStatusError as exc:
            logger.error("abuseipdb_blacklist_error", status=exc.response.status_code)
            return []
        except Exception as exc:
            logger.error("abuseipdb_blacklist_exception", error=str(exc))
            return []
