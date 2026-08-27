"""Unit tests for the Redis-backed SingleUseTokenStore (issue #267).

The payment callback replay guard must reject a replayed nonce even when
the second attempt arrives on a different app worker.  These tests verify
the store's Redis semantics (SET NX EX) across independent store
instances — the stand-in for separate worker processes — plus the
documented Redis-outage policy (fail-open, no exceptions, bounded
in-process fallback).
"""

import time

import pytest
from fakeredis import FakeRedis
from redis.exceptions import RedisError

from app.services.single_use_token import SingleUseTokenStore


@pytest.fixture
def redis():
    client = FakeRedis()
    yield client
    client.flushall()


def test_first_consume_claims_token_and_duplicate_is_rejected(redis):
    store = SingleUseTokenStore(key_prefix="test", redis_client=redis)

    assert store.consume("nonce-1", ttl_seconds=300) is True
    assert store.consume("nonce-1", ttl_seconds=300) is False


def test_duplicate_rejected_across_independent_store_instances(redis):
    """Two store instances backed by the same Redis must share the window."""
    store_a = SingleUseTokenStore(key_prefix="test", redis_client=redis)
    store_b = SingleUseTokenStore(key_prefix="test", redis_client=redis)

    assert store_a.consume("nonce-2", ttl_seconds=300) is True
    assert store_b.consume("nonce-2", ttl_seconds=300) is False


def test_replay_window_survives_worker_restart(redis):
    """A fresh process (empty in-memory state) must still see the window."""
    store_a = SingleUseTokenStore(key_prefix="test", redis_client=redis)
    assert store_a.consume("nonce-3", ttl_seconds=300) is True

    restarted_worker = SingleUseTokenStore(key_prefix="test", redis_client=redis)
    assert restarted_worker.consume("nonce-3", ttl_seconds=300) is False


def test_distinct_nonces_are_independent(redis):
    store = SingleUseTokenStore(key_prefix="test", redis_client=redis)

    assert store.consume("nonce-4", ttl_seconds=300) is True
    assert store.consume("nonce-5", ttl_seconds=300) is True


def test_token_becomes_reusable_after_ttl(redis):
    store = SingleUseTokenStore(key_prefix="test", redis_client=redis)

    assert store.consume("nonce-6", ttl_seconds=1) is True
    time.sleep(1.1)
    assert store.consume("nonce-6", ttl_seconds=1) is True


def test_redis_outage_fails_open_without_raising(redis, monkeypatch):
    """Redis down: claims succeed (fail-open), no exception, per-process replay still blocked."""
    store = SingleUseTokenStore(key_prefix="test", redis_client=redis)

    def boom(*args, **kwargs):
        raise RedisError("connection refused")

    monkeypatch.setattr(redis, "set", boom)

    # Fail-open: the first claim succeeds via the in-process fallback.
    assert store.consume("nonce-7", ttl_seconds=300) is True
    # The fallback still rejects an intra-process replay.
    assert store.consume("nonce-7", ttl_seconds=300) is False


def test_circuit_breaker_skips_redis_after_outage(redis, monkeypatch):
    """After a Redis failure the circuit opens and subsequent calls bypass Redis."""
    store = SingleUseTokenStore(key_prefix="test", redis_client=redis)

    def boom(*args, **kwargs):
        raise RedisError("connection refused")

    monkeypatch.setattr(redis, "set", boom)
    store.consume("nonce-8", ttl_seconds=300)
    assert store._circuit_open() is True

    # Restore Redis; while the circuit is open it must not be touched.
    called = {"n": 0}

    def spy(*args, **kwargs):
        called["n"] += 1
        return redis.set(*args, **kwargs)

    monkeypatch.setattr(redis, "set", spy)
    assert store.consume("nonce-9", ttl_seconds=300) is True
    assert called["n"] == 0


def test_flush_clears_tracked_tokens(redis):
    store = SingleUseTokenStore(key_prefix="test", redis_client=redis)

    assert store.consume("nonce-10", ttl_seconds=300) is True
    store.flush()
    assert store.consume("nonce-10", ttl_seconds=300) is True
