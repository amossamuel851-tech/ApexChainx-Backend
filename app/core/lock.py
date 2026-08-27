"""Distributed locking utilities for concurrency protection.

Provides advisory lock mechanisms using PostgreSQL's pg_advisory_xact_lock
to prevent concurrent execution of critical operations like SLA resolution
and recomputation.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.exceptions import ApexTransientError

logger = logging.getLogger(__name__)


class ConcurrencyLockError(ApexTransientError):
    """Raised when a lock cannot be acquired."""

    def __init__(self, detail: str = "Could not acquire lock.") -> None:
        super().__init__(detail=detail, error_code="concurrency_lock", status_code=409)


def _lock_id_from_key(key: str) -> int:
    """Convert a string key to a 64-bit integer for PostgreSQL advisory locks.

    Uses SHA-256 to generate a deterministic hash, then takes the first 8 bytes.
    The value must fit in a signed bigint: pg_advisory_xact_lock /
    pg_try_advisory_xact_lock accept bigint (signed 64-bit), and passing an
    unsigned value that exceeds 2**63 - 1 fails with
    "function pg_advisory_xact_lock(numeric) does not exist".
    """
    hash_bytes = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(hash_bytes[:8], byteorder="big", signed=True)


@contextmanager
def advisory_lock(db: Session, lock_key: str, timeout_seconds: float = 5.0) -> Generator[None, None, None]:
    """Acquire a PostgreSQL advisory lock for the duration of a transaction.

    This is a transaction-scoped lock that is automatically released when the
    transaction commits or rolls back.

    Args:
        db: SQLAlchemy session
        lock_key: Unique string identifier for the lock (e.g., "resolve:outage_123")
        timeout_seconds: Maximum time to wait for the lock (not directly enforced by PG,
                        but we can check before acquiring)

    Yields:
        None

    Raises:
        ConcurrencyLockError: If the lock cannot be acquired

    Example:
        with advisory_lock(db, f"resolve:{outage_id}"):
            # Critical section - only one transaction can execute this at a time
            outage = repo.resolve(outage_id, mttr_minutes)
            db.commit()
    """
    lock_id = _lock_id_from_key(lock_key)

    # Try to acquire the lock (non-blocking first check)
    result = db.execute(text("SELECT pg_try_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id})
    acquired = result.scalar()

    if not acquired:
        raise ConcurrencyLockError(f"Could not acquire lock for '{lock_key}'. Another operation is in progress.")

    try:
        yield
    except ApexTransientError:
        raise  # let domain errors propagate naturally
    except Exception as exc:
        logger.exception("Error inside advisory lock for '%s'", lock_key)
        raise ApexTransientError(detail=f"Unexpected error in locked section: {exc}") from exc


@contextmanager
def blocking_advisory_lock(db: Session, lock_key: str) -> Generator[None, None, None]:
    """Acquire a PostgreSQL advisory lock, blocking until it is available.

    Transaction-scoped: the lock is automatically released when the
    transaction commits or rolls back. Use for read-modify-write sequences
    that must be serialized (e.g. appending to the audit hash chain).

    Args:
        db: SQLAlchemy session
        lock_key: Unique string identifier for the lock

    Yields:
        None
    """
    lock_id = _lock_id_from_key(lock_key)
    db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id})
    try:
        yield
    finally:
        # The lock is released automatically when the transaction ends.
        pass


@contextmanager
def advisory_lock_nowait(db: Session, lock_key: str) -> Generator[None, None, None]:
    """Acquire a PostgreSQL advisory lock without waiting.

    Immediately fails if the lock is already held by another transaction.

    Args:
        db: SQLAlchemy session
        lock_key: Unique string identifier for the lock

    Yields:
        None

    Raises:
        ConcurrencyLockError: If the lock is already held

    Example:
        with advisory_lock_nowait(db, f"recompute:{outage_id}"):
            # Critical section
            stored_sla = sla_repo.create_if_changed(sla)
            db.commit()
    """
    lock_id = _lock_id_from_key(lock_key)

    result = db.execute(text("SELECT pg_try_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id})
    acquired = result.scalar()

    if not acquired:
        raise ConcurrencyLockError(f"Operation for '{lock_key}' is already in progress. Please retry later.")

    try:
        yield
    except ApexTransientError:
        raise  # let domain errors propagate
    except Exception as exc:
        logger.exception("Error inside advisory lock (nowait) for '%s'", lock_key)
        raise ApexTransientError(detail=f"Unexpected error in locked section: {exc}") from exc
