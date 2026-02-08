"""IOC matcher — checks observed values against the IOC database with caching."""

import time

from sqlalchemy import select

from ..models.ioc import IOC
from ..utils.logging import get_logger

logger = get_logger("intel.ioc_matcher")

# Default cache TTL in seconds
_CACHE_TTL = 60.0


class IOCMatcher:
    """Matches observed network artifacts against the IOC database.

    Uses an in-memory LRU-style cache with a 60-second TTL to minimize
    redundant database queries during high-frequency matching.
    """

    def __init__(self, db_session_factory) -> None:
        self._session_factory = db_session_factory
        # Cache: (ioc_type, value) -> (result_dict | None, timestamp)
        self._cache: dict[tuple[str, str], tuple[dict | None, float]] = {}

    def _cache_get(self, ioc_type: str, value: str) -> dict | None:
        """Retrieve a cached result if it exists and has not expired."""
        key = (ioc_type, value)
        if key in self._cache:
            result, ts = self._cache[key]
            if time.monotonic() - ts < _CACHE_TTL:
                return result
            # Expired — remove
            del self._cache[key]
        return None

    def _cache_set(self, ioc_type: str, value: str, result: dict | None) -> None:
        """Store a result in the cache with the current timestamp."""
        key = (ioc_type, value)
        self._cache[key] = (result, time.monotonic())

        # Simple eviction: if cache exceeds 10k entries, purge expired
        if len(self._cache) > 10_000:
            self._evict_expired()

    def _evict_expired(self) -> None:
        """Remove all expired entries from the cache."""
        now = time.monotonic()
        expired_keys = [
            k for k, (_, ts) in self._cache.items() if now - ts >= _CACHE_TTL
        ]
        for k in expired_keys:
            del self._cache[k]
        if expired_keys:
            logger.debug("ioc_cache_evicted", count=len(expired_keys))

    async def _check_values(self, ioc_type: str, values: list[str]) -> list[dict]:
        """Core query method: check a list of values of a given IOC type.

        Uses the cache for values already seen recently. Queries the database
        for uncached values and caches the results.

        Returns a list of matched IOC dictionaries (only matches, not misses).
        """
        if not values:
            return []

        matches: list[dict] = []
        uncached_values: list[str] = []

        # Check cache first
        for val in values:
            cached = self._cache_get(ioc_type, val)
            if cached is not None:
                matches.append(cached)
            elif (ioc_type, val) not in self._cache:
                # Not in cache at all — need to query
                uncached_values.append(val)
            # else: in cache but None (known non-match, still valid TTL)

        if not uncached_values:
            return matches

        # Query database for uncached values
        try:
            async with self._session_factory() as session:
                result = await session.execute(
                    select(IOC).where(
                        IOC.ioc_type == ioc_type,
                        IOC.value.in_(uncached_values),
                        IOC.active == True,  # noqa: E712
                    )
                )
                db_iocs = result.scalars().all()

                # Index found IOCs by value
                found_map: dict[str, IOC] = {ioc.value: ioc for ioc in db_iocs}

                for val in uncached_values:
                    if val in found_map:
                        ioc = found_map[val]
                        match_dict = {
                            "ioc_type": ioc.ioc_type,
                            "value": ioc.value,
                            "severity": ioc.severity,
                            "source": ioc.source,
                            "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                            "tags_json": ioc.tags_json,
                            "context_json": ioc.context_json,
                            "feed_id": ioc.feed_id,
                        }
                        self._cache_set(ioc_type, val, match_dict)
                        matches.append(match_dict)
                    else:
                        # Cache the miss to avoid re-querying
                        self._cache_set(ioc_type, val, None)

        except Exception as exc:
            logger.error("ioc_matcher_query_error", ioc_type=ioc_type, error=str(exc))

        return matches

    async def check_ips(self, ips: list[str]) -> list[dict]:
        """Check a list of IP addresses against the IOC database.

        Returns matching IOC records.
        """
        return await self._check_values("ip", ips)

    async def check_domains(self, domains: list[str]) -> list[dict]:
        """Check a list of domain names against the IOC database.

        Returns matching IOC records.
        """
        return await self._check_values("domain", domains)

    async def check_urls(self, urls: list[str]) -> list[dict]:
        """Check a list of URLs against the IOC database.

        Returns matching IOC records.
        """
        return await self._check_values("url", urls)

    async def check_hashes(self, hashes: list[str]) -> list[dict]:
        """Check a list of file hashes against the IOC database.

        Returns matching IOC records.
        """
        return await self._check_values("hash", hashes)
