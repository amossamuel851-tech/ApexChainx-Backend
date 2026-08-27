"""Redis-backed single-use token store with a bounded in-process fallback.

Used for replay protection (payment callback nonces) and idempotency-key
claims.  ``consume`` atomically claims a token with Redis ``SET NX EX``:
it returns ``True`` the first time a token is seen and ``False`` for every
subsequent attempt within the TTL window — including attempts made from a
different process or worker that shares the same Redis.

Redis outage policy (fail-open)
------------------------------
When Redis is unreachable the store falls back to a bounded in-process
dict, so an outage does not turn into a 500 for callers.  This mirrors the
auth rate limiter (``app/core/rate_limiter.py``) and the idempotency
middleware (``app/middleware/idempotency.py``): availability is preferred
over strictness, and the replay-protection guarantee degrades to
per-process for the duration of the outage.  A 30-second circuit breaker
avoids hammering a dead Redis on every request.
"""

import logging
import time
from threading import Lock

from redis import Redis
from redis.exceptions import RedisError

from app.core.config import settings

logger = logging.getLogger(__name__)

_CIRCUIT_OPEN_TTL_SECONDS = 30.0


class SingleUseTokenStore:
    """Claim single-use tokens with Redis ``SET NX EX`` semantics.

    Args:
        key_prefix: Namespace prefix for Redis keys so different token
            classes (callback nonces, idempotency keys, ...) never collide.
        redis_client: Optional pre-configured Redis client.  Defaults to a
            client built from ``settings.CELERY_BROKER_URL`` so every
            process shares the same store.
    """

    def __init__(self, key_prefix: str, redis_client: Redis | None = None) -> None:
        self._key_prefix = key_prefix
        self._redis = redis_client or Redis.from_url(settings.CELERY_BROKER_URL)
        # Bounded in-process fallback: {token: monotonic timestamp}.
        self._seen: dict[str, float] = {}
        self._lock = Lock()
        self._disabled_until: float = 0.0

    def _redis_key(self, token: str) -> str:
        return f"{self._key_prefix}:{token}"

    def _circuit_open(self) -> bool:
        return time.monotonic() < self._disabled_until

    def _trip_circuit(self) -> None:
        self._disabled_until = time.monotonic() + _CIRCUIT_OPEN_TTL_SECONDS
        logger.warning(
            "SingleUseTokenStore: Redis unavailable, circuit tripped for %.0f seconds",
            _CIRCUIT_OPEN_TTL_SECONDS,
        )

    def consume(self, token: str, ttl_seconds: int) -> bool:
        """Atomically claim *token*; ``True`` if this call won the claim.

        Within the TTL window every call with the same token returns
        ``False``, including calls from other processes sharing the same
        Redis.  When Redis is unavailable the claim falls back to
        per-process state (fail-open, see module docstring).
        """
        if self._circuit_open():
            return self._consume_in_process(token, ttl_seconds)

        try:
            claimed = self._redis.set(self._redis_key(token), "1", ex=ttl_seconds, nx=True)
        except (RedisError, OSError) as exc:
            logger.warning("SingleUseTokenStore: Redis SET NX failed (%s); using in-process fallback", exc)
            self._trip_circuit()
            return self._consume_in_process(token, ttl_seconds)

        if claimed is None:
            return False
        return True

    def _consume_in_process(self, token: str, ttl_seconds: int) -> bool:
        """Per-process replay window used when Redis is unavailable."""
        cutoff = time.monotonic() - ttl_seconds
        with self._lock:
            stale = [k for k, ts in self._seen.items() if ts < cutoff]
            for k in stale:
                del self._seen[k]
            if token in self._seen:
                return False
            self._seen[token] = time.monotonic()
            return True

    def flush(self) -> None:
        """Delete all tracked tokens (tests and operational tooling)."""
        try:
            keys = self._redis.keys(f"{self._key_prefix}:*")
            if keys:
                self._redis.delete(*keys)
        except RedisError:
            pass
        with self._lock:
            self._seen.clear()
