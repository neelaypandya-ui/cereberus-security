"""Tests for VirusTotalProvider — hash and IP lookups with rate limiting."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.intel.virustotal import VirusTotalProvider


def _mock_httpx_response(status_code=200, json_data=None):
    """Create a mock httpx Response."""
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data or {}
    response.raise_for_status = MagicMock()
    return response


class TestLookupHash:
    @pytest.mark.asyncio
    async def test_lookup_hash(self):
        """lookup_hash should parse the VT response into normalized IOC format."""
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 12,
                        "suspicious": 3,
                        "undetected": 50,
                        "harmless": 5,
                    },
                    "meaningful_name": "trojan.exe",
                    "type_description": "Win32 EXE",
                    "reputation": -45,
                }
            }
        }
        mock_response = _mock_httpx_response(status_code=200, json_data=vt_response)

        provider = VirusTotalProvider(api_key="test-api-key")
        # Reset rate limit timer so we do not wait
        provider._last_request_time = 0.0

        with patch("backend.intel.virustotal.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await provider.lookup_hash("abc123def456")

        assert result["ioc_type"] == "hash"
        assert result["value"] == "abc123def456"
        assert result["source"] == "virustotal"
        assert result["severity"] == "critical"  # 12 malicious >= 10
        assert result["context"]["found"] is True
        assert result["context"]["malicious"] == 12
        assert result["context"]["meaningful_name"] == "trojan.exe"


class TestLookupIP:
    @pytest.mark.asyncio
    async def test_lookup_ip(self):
        """lookup_ip should parse VT IP response into normalized IOC format."""
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "undetected": 60,
                        "harmless": 10,
                    },
                    "country": "RU",
                    "as_owner": "Evil Corp ISP",
                    "reputation": -10,
                    "network": "198.51.100.0/24",
                }
            }
        }
        mock_response = _mock_httpx_response(status_code=200, json_data=vt_response)

        provider = VirusTotalProvider(api_key="test-api-key")
        provider._last_request_time = 0.0

        with patch("backend.intel.virustotal.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await provider.lookup_ip("198.51.100.5")

        assert result["ioc_type"] == "ip"
        assert result["value"] == "198.51.100.5"
        assert result["source"] == "virustotal"
        assert result["severity"] == "medium"  # 3 malicious + 1 suspicious = 4 >= 2
        assert result["context"]["country"] == "RU"
        assert result["context"]["as_owner"] == "Evil Corp ISP"


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """Rate limiter should enforce 15-second intervals (4 req/min)."""
        provider = VirusTotalProvider(api_key="test-api-key")

        # Simulate a recent request
        provider._last_request_time = time.monotonic()

        start = time.monotonic()

        with patch("backend.intel.virustotal.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await provider._rate_limit()

            # asyncio.sleep should have been called with a positive wait time
            mock_sleep.assert_called_once()
            wait_arg = mock_sleep.call_args[0][0]
            # The wait should be close to 15 seconds (the rate limit interval)
            assert 0 < wait_arg <= 15.0
