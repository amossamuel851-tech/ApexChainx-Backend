"""Idempotency middleware for state-changing endpoints.

Reads the Idempotency-Key header on POST/PUT/PATCH/DELETE requests, caches
responses in Redis, and replays them on duplicate requests with the same key.

Fix #312: Only cache 2xx responses. 5xx responses are never cached so the
          key can be retried after a transient server error.
Fix #313: Cache keys are scoped per-user by hashing the Authorization bearer
          token, so two different users cannot collide on the same key.
Fix #314: Redis failures are handled with a 30-second circuit breaker. When
          the circuit is open the middleware fails-open (passes the request
          through) rather than returning a 500.
"""

import hashlib
import json
import logging
import time

from fastapi import Request, Response
from redis import Redis
from redis.exceptions import RedisError
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.services.formatters import canonical_json
from app.services.single_use_token import SingleUseTokenStore

logger = logging.getLogger(__name__)

# How long (seconds) to disable Redis after a failure (#314 circuit breaker)
_CIRCUIT_OPEN_TTL = 30

# Marker written by the claim step while a request is still in flight (see
# SingleUseTokenStore.consume).  A cached response is always a JSON object,
# so this short value can never be confused with one.
_IN_FLIGHT_MARKER = "1"


def _compute_fingerprint(method: str, path: str, body: bytes) -> str:
    canonical = canonical_json(json.loads(body if body else b"{}")) if body else "{}"
    raw = f"{method}:{path}:{canonical}".encode()
    return hashlib.sha256(raw).hexdigest()


def _actor_key(request: Request) -> str:
    """Return a short user-scoped hash derived from the Authorization header.

    If no Authorization header is present (unauthenticated request) an empty
    string is returned so the key is still namespaced but not user-scoped.
    """
    auth_header = request.headers.get("Authorization", "")
    # Strip the "Bearer " prefix if present, fall back to the full value
    token = auth_header.removeprefix("Bearer ").strip()
    if not token:
        return ""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


class IdempotencyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, redis_client: Redis | None = None):
        super().__init__(app)
        self.redis = redis_client or Redis.from_url(settings.CELERY_BROKER_URL)
        self.ttl = settings.IDEMPOTENCY_KEY_TTL_HOURS * 3600
        # Issue #267: the key is claimed atomically (SET NX EX) before the
        # request is processed, so two concurrent requests with the same key
        # cannot both run the side effects.  The claim shares the single-use
        # token store used by the payment callback replay guard.
        self.single_use = SingleUseTokenStore(key_prefix="idempotency", redis_client=self.redis)
        # Circuit-breaker state (#314): timestamp until which Redis is skipped
        self._disabled_until: float = 0.0

    # ------------------------------------------------------------------
    # Internal Redis helpers with circuit-breaker (#314)
    # ------------------------------------------------------------------

    def _circuit_open(self) -> bool:
        return time.monotonic() < self._disabled_until

    def _trip_circuit(self) -> None:
        self._disabled_until = time.monotonic() + _CIRCUIT_OPEN_TTL
        logger.warning(
            "Idempotency middleware: Redis unavailable, circuit tripped for %d seconds",
            _CIRCUIT_OPEN_TTL,
        )

    def _redis_get(self, key: str):
        """Return the cached value or None.  Returns None on Redis failure."""
        if self._circuit_open():
            return None
        try:
            return self.redis.get(key)
        except RedisError as exc:
            logger.warning("Idempotency middleware: Redis GET failed: %s", exc)
            self._trip_circuit()
            return None

    def _redis_setex(self, key: str, ttl: int, value: str) -> None:
        """Store a value with expiry. Silently fails on Redis error."""
        if self._circuit_open():
            return
        try:
            self.redis.setex(key, ttl, value)
        except RedisError as exc:
            logger.warning("Idempotency middleware: Redis SETEX failed: %s", exc)
            self._trip_circuit()

    def _redis_delete(self, key: str) -> None:
        """Delete a key (used to release a claim on non-2xx responses)."""
        if self._circuit_open():
            return
        try:
            self.redis.delete(key)
        except RedisError as exc:
            logger.warning("Idempotency middleware: Redis DEL failed: %s", exc)
            self._trip_circuit()

    # ------------------------------------------------------------------
    # Middleware dispatch
    # ------------------------------------------------------------------

    async def dispatch(self, request: Request, call_next):
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return await call_next(request)

        idempotency_key = request.headers.get("Idempotency-Key")
        if not idempotency_key:
            return await call_next(request)

        body = await request.body()
        fingerprint = _compute_fingerprint(request.method, request.url.path, body)

        # #313: scope the key to the authenticated user; the store adds the
        # "idempotency:" namespace prefix.
        actor = _actor_key(request)
        token = f"{actor}:{idempotency_key}"
        cache_key = self.single_use.key_for(token)

        # Issue #267: atomically claim the key before processing.  A failed
        # claim means the key was already used (cached response to replay) or
        # is in flight on another worker (409 while the first request runs).
        claimed = self.single_use.consume(token, self.ttl)
        if not claimed:
            existing = self._redis_get(cache_key)
            if existing is None or existing == _IN_FLIGHT_MARKER.encode():
                return Response(
                    status_code=409,
                    content=json.dumps({"detail": "Idempotency-Key already in use"}),
                    media_type="application/json",
                )
            cached = json.loads(existing)
            if cached["fingerprint"] != fingerprint:
                return Response(
                    status_code=409,
                    content=json.dumps({"detail": "Idempotency-Key already used with different payload"}),
                    media_type="application/json",
                )
            return Response(
                status_code=cached["status_code"],
                content=cached["body"],
                media_type=cached.get("media_type", "application/json"),
                headers={"Content-Location": f"{request.url.path}"},
            )

        response = await call_next(request)
        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk

        # #312: only cache successful (2xx) responses; 5xx are never cached so
        # the caller can safely retry with the same Idempotency-Key.  Non-2xx
        # responses release the claim so a retry is not blocked.
        if 200 <= response.status_code < 300:
            cached_response = {
                "fingerprint": fingerprint,
                "status_code": response.status_code,
                "body": response_body.decode(),
                "media_type": response.media_type or "application/json",
            }
            self._redis_setex(cache_key, self.ttl, json.dumps(cached_response))
        else:
            self._redis_delete(cache_key)

        return Response(
            status_code=response.status_code,
            content=response_body,
            media_type=response.media_type,
            headers=dict(response.headers),
        )
