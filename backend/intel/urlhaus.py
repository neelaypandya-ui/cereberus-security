"""URLhaus threat intelligence provider (no API key required)."""

import httpx

from ..utils.logging import get_logger

logger = get_logger("intel.urlhaus")

_URLHAUS_BASE_URL = "https://urlhaus-api.abuse.ch/v1"


class URLhausProvider:
    """URLhaus API provider for recent malicious URLs and payloads.

    This provider does not require an API key.
    """

    def _severity_from_threat(self, threat_type: str, tags: list) -> str:
        """Derive severity from URLhaus threat type and tags."""
        high_threats = {"malware_download", "c2", "payload_delivery"}
        if threat_type in high_threats:
            return "high"
        ransomware_tags = {"emotet", "qakbot", "icedid", "cobalt_strike", "ransomware"}
        if any(tag.lower() in ransomware_tags for tag in tags):
            return "critical"
        if threat_type:
            return "medium"
        return "low"

    async def fetch_recent_urls(self, limit: int = 100) -> list[dict]:
        """Fetch recently added malicious URLs from URLhaus.

        Returns a list of normalized IOC format dictionaries.
        """
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{_URLHAUS_BASE_URL}/urls/recent/",
                    data={"limit": limit},
                )
                response.raise_for_status()
                data = response.json()
                urls = data.get("urls", [])

                iocs = []
                for entry in urls:
                    url_value = entry.get("url", "")
                    threat = entry.get("threat", "")
                    tags = entry.get("tags") or []
                    if isinstance(tags, str):
                        tags = [t.strip() for t in tags.split(",") if t.strip()]

                    iocs.append({
                        "ioc_type": "url",
                        "value": url_value,
                        "severity": self._severity_from_threat(threat, tags),
                        "source": "urlhaus",
                        "context": {
                            "threat": threat,
                            "tags": tags,
                            "url_status": entry.get("url_status"),
                            "host": entry.get("host"),
                            "date_added": entry.get("date_added"),
                            "reporter": entry.get("reporter"),
                            "urlhaus_reference": entry.get("urlhaus_reference"),
                        },
                    })
                logger.info("urlhaus_urls_fetched", count=len(iocs))
                return iocs
        except httpx.HTTPStatusError as exc:
            logger.error("urlhaus_urls_error", status=exc.response.status_code)
            return []
        except Exception as exc:
            logger.error("urlhaus_urls_exception", error=str(exc))
            return []

    async def fetch_payloads(self, limit: int = 50) -> list[dict]:
        """Fetch recently observed payloads from URLhaus.

        Returns a list of normalized IOC format dictionaries (hash-type IOCs).
        """
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{_URLHAUS_BASE_URL}/payloads/recent/",
                    data={"limit": limit},
                )
                response.raise_for_status()
                data = response.json()
                payloads = data.get("payloads", [])

                iocs = []
                for entry in payloads:
                    sha256 = entry.get("sha256_hash", "")
                    if not sha256:
                        continue

                    file_type = entry.get("file_type") or ""
                    signature = entry.get("signature") or ""
                    tags = entry.get("tags") or []
                    if isinstance(tags, str):
                        tags = [t.strip() for t in tags.split(",") if t.strip()]

                    # Determine severity from VT detection count and signature
                    vt_percent = entry.get("virustotal", {}).get("percent") if entry.get("virustotal") else None
                    if vt_percent is not None and vt_percent >= 50:
                        severity = "critical"
                    elif vt_percent is not None and vt_percent >= 25:
                        severity = "high"
                    elif signature:
                        severity = "high"
                    else:
                        severity = "medium"

                    iocs.append({
                        "ioc_type": "hash",
                        "value": sha256,
                        "severity": severity,
                        "source": "urlhaus",
                        "context": {
                            "md5_hash": entry.get("md5_hash"),
                            "sha256_hash": sha256,
                            "file_type": file_type,
                            "file_size": entry.get("file_size"),
                            "signature": signature,
                            "tags": tags,
                            "firstseen": entry.get("firstseen"),
                            "lastseen": entry.get("lastseen"),
                            "url_count": entry.get("url_count"),
                            "urlhaus_download": entry.get("urlhaus_download"),
                            "virustotal": entry.get("virustotal"),
                        },
                    })
                logger.info("urlhaus_payloads_fetched", count=len(iocs))
                return iocs
        except httpx.HTTPStatusError as exc:
            logger.error("urlhaus_payloads_error", status=exc.response.status_code)
            return []
        except Exception as exc:
            logger.error("urlhaus_payloads_exception", error=str(exc))
            return []
