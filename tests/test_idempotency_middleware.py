"""Tests for the idempotency middleware's atomic key claim (issue #267).

The middleware now claims each Idempotency-Key atomically (SET NX EX)
through the same single-use token store used by the payment callback
replay guard, so two concurrent requests with the same key cannot both
run their side effects, and non-2xx responses release the claim.
"""

import pytest
from fakeredis import FakeRedis
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from fastapi.testclient import TestClient

from app.middleware.idempotency import IdempotencyMiddleware


async def ok_endpoint(request):
    return JSONResponse({"ok": True, "processed": "yes"})


async def failing_endpoint(request):
    return JSONResponse({"error": "nope"}, status_code=400)


test_app = Starlette(
    routes=[
        Route("/ok", ok_endpoint, methods=["POST"]),
        Route("/fail", failing_endpoint, methods=["POST"]),
    ]
)


@pytest.fixture
def mw_client():
    redis = FakeRedis()
    middleware = IdempotencyMiddleware(test_app, redis_client=redis)
    return TestClient(middleware), redis


def _cache_key(idempotency_key: str) -> str:
    # No Authorization header in these tests, so the actor scope is empty.
    return f"idempotency::{idempotency_key}"


class TestCachedReplay:
    def test_same_key_replays_cached_response(self, mw_client):
        client, _ = mw_client

        first = client.post("/ok", json={"a": 1}, headers={"Idempotency-Key": "key-1"})
        assert first.status_code == 200
        second = client.post("/ok", json={"a": 1}, headers={"Idempotency-Key": "key-1"})
        assert second.status_code == 200
        assert second.json() == first.json()

    def test_different_payload_with_same_key_conflicts(self, mw_client):
        client, _ = mw_client

        first = client.post("/ok", json={"a": 1}, headers={"Idempotency-Key": "key-2"})
        assert first.status_code == 200

        conflict = client.post("/ok", json={"a": 2}, headers={"Idempotency-Key": "key-2"})
        assert conflict.status_code == 409
        assert "different payload" in conflict.json()["detail"]

    def test_different_keys_are_independent(self, mw_client):
        client, _ = mw_client

        first = client.post("/ok", json={}, headers={"Idempotency-Key": "key-3"})
        second = client.post("/ok", json={}, headers={"Idempotency-Key": "key-4"})
        assert first.status_code == 200
        assert second.status_code == 200


class TestClaimRelease:
    def test_non_2xx_releases_claim_so_retry_is_not_blocked(self, mw_client):
        client, _ = mw_client

        first = client.post("/fail", json={}, headers={"Idempotency-Key": "key-5"})
        assert first.status_code == 400
        # The claim was released: a retry re-processes instead of 409.
        second = client.post("/fail", json={}, headers={"Idempotency-Key": "key-5"})
        assert second.status_code == 400

    def test_in_flight_key_returns_409(self, mw_client):
        """A key claimed but not yet completed is reported as in use (409)."""
        client, redis = mw_client
        key = "key-6"
        # Simulate a request that claimed the key and is still processing.
        # The middleware's token is "{actor}:{key}" with an empty actor scope.
        store = IdempotencyMiddleware(test_app, redis_client=redis).single_use
        assert store.consume(f":{key}", ttl_seconds=3600) is True

        resp = client.post("/ok", json={}, headers={"Idempotency-Key": key})
        assert resp.status_code == 409
        assert "already in use" in resp.json()["detail"]
