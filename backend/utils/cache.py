"""TTL Cache — in-memory cache with time-based expiration."""

import asyncio
import time
from typing import Any, Callable, Awaitable, Optional

from ..utils.logging import get_logger

logger = get_logger("utils.cache")


class TTLCache:
    """Thread-safe in-memory cache with per-key TTL expiration."""

    def __init__(self, default_ttl: float = 30.0, max_entries: int = 1000):
        self._default_ttl = default_ttl
        self._max_entries = max_entries
        self._store: dict[str, tuple[Any, float]] = {}  # key -> (value, expires_at)
        self._lock = asyncio.Lock()

    def get(self, key: str) -> Any | None:
        """Get a cached value if it exists and hasn't expired."""
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        """Set a cached value with optional custom TTL."""
        self._evict_if_full()
        expires_at = time.monotonic() + (ttl if ttl is not None else self._default_ttl)
        self._store[key] = (value, expires_at)

    def invalidate(self, key: str) -> None:
        """Remove a specific key from the cache."""
        self._store.pop(key, None)

    def clear(self) -> None:
        """Clear all cached entries."""
        self._store.clear()

    async def get_or_compute(
        self,
        key: str,
        compute_fn: Callable[[], Awaitable[Any]],
        ttl: float | None = None,
    ) -> Any:
        """Get cached value or compute it if missing/expired.

        Uses an asyncio lock to prevent thundering herd on the same key.
        """
        cached = self.get(key)
        if cached is not None:
            return cached

        async with self._lock:
            # Double-check after acquiring lock
            cached = self.get(key)
            if cached is not None:
                return cached

            value = await compute_fn()
            self.set(key, value, ttl)
            return value

    def _evict_if_full(self) -> None:
        """Evict expired entries first, then oldest if still full."""
        # Remove expired
        now = time.monotonic()
        expired_keys = [k for k, (_, exp) in self._store.items() if now > exp]
        for k in expired_keys:
            del self._store[k]

        # If still over limit, remove oldest entries
        if len(self._store) >= self._max_entries:
            sorted_keys = sorted(self._store, key=lambda k: self._store[k][1])
            to_remove = len(self._store) - self._max_entries + 1
            for k in sorted_keys[:to_remove]:
                del self._store[k]
