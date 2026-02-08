"""Simple in-memory rate limiter for login endpoints."""

import time
from collections import defaultdict


class RateLimiter:
    """Sliding window rate limiter keyed by identifier (e.g., IP address)."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def is_rate_limited(self, key: str) -> bool:
        """Check if the key has exceeded the rate limit.

        Returns True if rate limited, False if allowed.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Prune old entries
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]

        return len(self._attempts[key]) >= self.max_attempts

    def record_attempt(self, key: str) -> None:
        """Record an attempt for the given key."""
        now = time.time()
        cutoff = now - self.window_seconds

        # Prune old entries
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]
        self._attempts[key].append(now)

        # Bounded cleanup: if too many keys, prune stale ones (limit 100 per call)
        if len(self._attempts) > 10000:
            pruned = 0
            keys_to_remove = []
            for k in list(self._attempts.keys()):
                if pruned >= 100:
                    break
                self._attempts[k] = [t for t in self._attempts[k] if t > cutoff]
                if not self._attempts[k]:
                    keys_to_remove.append(k)
                pruned += 1
            for k in keys_to_remove:
                del self._attempts[k]

    def remaining_attempts(self, key: str) -> int:
        """Get remaining attempts before rate limiting."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]
        return max(0, self.max_attempts - len(self._attempts[key]))

    def reset(self, key: str) -> None:
        """Reset rate limit for a key."""
        self._attempts.pop(key, None)
