import json
import logging
import random
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Lock, Semaphore
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.tracing import get_current_traceparent, traced
from app.models.webhook import Webhook, WebhookDelivery, WebhookDeliveryStatus, WebhookEvent
from app.services.formatters import canonical_json
from app.services.metrics import increment_counter
from app.services.secret_encryption import decrypt_secret
from app.services.webhook_breaker import breaker
from app.services.webhook_signing import (
    CURRENT_SIGNATURE_VERSION,
    sign_payload,
)
from app.utils.correlation_ctx import get_or_generate_correlation_id
from app.utils.network_validation import NetworkValidationError, validate_webhook_url

logger = logging.getLogger(__name__)


class WebhookDispatchLimiter:
    """Limit concurrent webhook delivery attempts globally and per webhook."""

    def __init__(self, global_limit: int = 10, per_webhook_limit: int = 5) -> None:
        self._global_semaphore = Semaphore(max(1, global_limit))
        self._per_webhook_limit = max(1, per_webhook_limit)
        self._per_webhook_semaphores: dict[str, Semaphore] = {}
        self._lock = Lock()

    def _get_per_webhook_semaphore(self, webhook_id: str) -> Semaphore:
        with self._lock:
            semaphore = self._per_webhook_semaphores.get(webhook_id)
            if semaphore is None:
                semaphore = Semaphore(self._per_webhook_limit)
                self._per_webhook_semaphores[webhook_id] = semaphore
            return semaphore

    @contextmanager
    def acquire(self, webhook_id: str) -> Iterator[None]:
        self._global_semaphore.acquire()
        try:
            semaphore = self._get_per_webhook_semaphore(webhook_id)
            semaphore.acquire()
            yield
        finally:
            semaphore.release()
            self._global_semaphore.release()


dispatch_limiter = WebhookDispatchLimiter(
    global_limit=settings.WEBHOOK_MAX_CONCURRENT_DISPATCHES,
    per_webhook_limit=settings.WEBHOOK_MAX_CONCURRENT_DISPATCHES_PER_WEBHOOK,
)


def _get_retry_delays() -> list[int]:
    """Parse WEBHOOK_RETRY_BASE_DELAYS from settings into a list of ints."""
    return [int(d.strip()) for d in settings.WEBHOOK_RETRY_BASE_DELAYS.split(",") if d.strip()]


def _apply_jitter(delay: float) -> float:
    """Apply jitter to a retry delay based on WEBHOOK_RETRY_JITTER config."""
    mode = getattr(settings, "WEBHOOK_RETRY_JITTER", "full")
    if mode == "none":
        return delay
    if mode == "equal":
        return delay * random.uniform(0.5, 1.5)  # nosec B311 - retry jitter, not security
    # "full" (default): random in [0, nominal*2], floor 1s
    return max(1.0, random.uniform(0, delay * 2))  # nosec B311 - retry jitter, not security


WEBHOOK_SCHEMA_VERSION = "1"
# BE-299: cap on due deliveries processed per retry sweep, so a large backlog
# (e.g. after an outage burst) can't block the worker for an unbounded run.
WEBHOOK_RETRY_BATCH_SIZE = 100

# Response bodies are receiver-controlled; cap and scrub before persisting (#301).
RESPONSE_BODY_STORAGE_LIMIT = 500
_SCRUB_PATTERNS = [
    re.compile(r"S[A-Za-z0-9]{55}"),  # Stellar secret key
    re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S+"),
]


def _scrub_response_body(body: str) -> str:
    """Redact likely-sensitive patterns and bound the stored size (#301)."""
    scrubbed = body
    for pattern in _SCRUB_PATTERNS:
        scrubbed = pattern.sub("[REDACTED]", scrubbed)
    return scrubbed[:RESPONSE_BODY_STORAGE_LIMIT]


def _build_headers(
    webhook: Webhook,
    payload: str,
    event: WebhookEvent = WebhookEvent.SLA_VIOLATION,
    signature_version: int = CURRENT_SIGNATURE_VERSION,
) -> dict[str, str]:
    """Build webhook delivery headers with explicit signature versioning (BE-087).

    Args:
        webhook: Webhook configuration
        payload: JSON payload string
        event: Webhook event type
        signature_version: Explicit signature algorithm version

    Returns:
        Dictionary of headers including:
        - Content-Type: application/json
        - X-Webhook-Event: event type
        - X-Webhook-Timestamp: ISO-formatted UTC timestamp
        - X-Webhook-Signature: signature (if secret configured)
        - X-Webhook-Signature-Version: signature version (if secret configured)
        - traceparent: W3C trace context for distributed tracing (from OTel)
    """
    corr_id = get_or_generate_correlation_id()

    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Event": event.value,
        "X-Webhook-Timestamp": datetime.now(UTC).isoformat(),
        "X-Correlation-ID": corr_id,
    }

    # Inject OTel trace context (traceparent) only when a real span is active
    # (#300): a correlation ID is not a trace ID, and fabricating one here
    # produced fake sampled root traces with no real parent linkage.
    traceparent = get_current_traceparent()
    if traceparent:
        headers["traceparent"] = traceparent

    # The secret is encrypted at rest (#266); recover the plaintext only
    # here, at signing time, so a database leak never exposes live keys.
    secret = decrypt_secret(webhook.secret)
    if secret:
        sig_hex, _ = sign_payload(secret, payload, signature_version)
        headers["X-Webhook-Signature"] = f"sha256={sig_hex}"
        headers["X-Webhook-Signature-Version"] = str(signature_version)
    return headers


def get_active_webhooks_for_event(db: Session, event: WebhookEvent) -> list[Webhook]:
    # NOTE: full-table scan + per-row json.loads is a known N+1 (issue #294).
    # The durable fix (JSONB column + SQL containment filter, or a normalized
    # webhook_events join table) needs a schema migration and is tracked
    # separately; this only stops corrupt rows from being silently dropped.
    webhooks = db.query(Webhook).filter(Webhook.is_active).all()
    result = []
    for webhook in webhooks:
        try:
            events = json.loads(webhook.events)
            if event.value in events:
                result.append(webhook)
        except (json.JSONDecodeError, TypeError):
            logger.error("Webhook %s has invalid events JSON, skipping.", webhook.id)
            increment_counter("webhook.events_json.corrupt", tags={"webhook_id": str(webhook.id)})
    return result


def create_delivery(
    db: Session,
    webhook: Webhook,
    event: WebhookEvent,
    payload: dict[str, Any],
    signature_version: int = CURRENT_SIGNATURE_VERSION,
) -> WebhookDelivery:
    """Create a webhook delivery record with explicit signature version (BE-087).

    Args:
        db: Database session
        webhook: Webhook configuration
        event: Webhook event type
        payload: Event payload dict (will be JSON-serialized)
        signature_version: Signature algorithm version to use

    Returns:
        Created WebhookDelivery record
    """
    delivery = WebhookDelivery(
        webhook_id=webhook.id,
        event=event,
        payload=canonical_json(payload),
        status=WebhookDeliveryStatus.PENDING,
        signature_version=signature_version,
    )
    db.add(delivery)
    db.commit()
    db.refresh(delivery)
    return delivery


def _attempt_delivery(delivery: WebhookDelivery, webhook: Webhook) -> bool:
    payload_str = delivery.payload
    headers = _build_headers(
        webhook,
        payload_str,
        delivery.event,
        delivery.signature_version,
    )

    # Re-validate the webhook URL before every delivery attempt to mitigate DNS rebinding.
    current_ips = validate_webhook_url(webhook.url)

    # Pin delivery to the addresses approved at registration (issue #295): if the
    # webhook was registered with a resolved_ips snapshot and delivery-time
    # resolution no longer overlaps it at all, fail closed rather than silently
    # following the new (possibly rebound) address. Redirect-target validation
    # and a configurable warn/allow policy are follow-ups, tracked in #295.
    if webhook.resolved_ips:
        try:
            approved_ips = set(json.loads(webhook.resolved_ips))
        except (json.JSONDecodeError, TypeError):
            approved_ips = set()
        if approved_ips and not (approved_ips & set(current_ips)):
            logger.error(
                "Webhook %s delivery blocked: resolved IPs %s do not match approved %s (possible DNS rebinding).",
                webhook.id,
                current_ips,
                approved_ips,
            )
            raise NetworkValidationError("Webhook host resolution no longer matches the approved address.")

    # Check circuit breaker before attempting
    if not breaker.allow_request(webhook.url):
        delivery.status = WebhookDeliveryStatus.BREAKER_OPEN
        delivery.error_message = "Circuit breaker open, delivery deferred"
        logger.warning("Webhook delivery %s deferred: circuit breaker open for %s.", delivery.id, webhook.url)
        return False

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(webhook.url, content=payload_str, headers=headers)
        delivery.response_status_code = response.status_code
        delivery.response_body = _scrub_response_body(response.text)

        if response.is_success:
            breaker.on_success(webhook.url)
            return True
        else:
            breaker.on_failure(webhook.url)
            delivery.error_message = f"Non-success status: {response.status_code}"
            return False

    except httpx.TimeoutException as exc:
        breaker.on_failure(webhook.url)
        delivery.error_message = f"Request timed out: {exc}"
        logger.warning("Webhook delivery %s timed out.", delivery.id)
        return False
    except httpx.RequestError as exc:
        breaker.on_failure(webhook.url)
        delivery.error_message = f"Request error: {exc}"
        logger.warning("Webhook delivery %s failed with request error: %s", delivery.id, exc)
        return False


@traced("webhook.dispatch")
def dispatch_delivery(db: Session, delivery_id: UUID) -> None:
    delivery = db.query(WebhookDelivery).filter(WebhookDelivery.id == delivery_id).first()
    if not delivery:
        logger.error("WebhookDelivery %s not found.", delivery_id)
        return

    if delivery.status in (WebhookDeliveryStatus.SUCCESS, WebhookDeliveryStatus.DEAD_LETTER):
        logger.info("WebhookDelivery %s already in terminal state %s, skipping.", delivery_id, delivery.status)
        return

    webhook = delivery.webhook

    # If breaker is open, mark as breaker_open without consuming retry budget
    if not breaker.allow_request(webhook.url):
        delivery.status = WebhookDeliveryStatus.BREAKER_OPEN
        delivery.error_message = "Circuit breaker open, delivery deferred"
        delivery.next_retry_at = datetime.now(UTC) + timedelta(seconds=settings.WEBHOOK_BREAKER_RESET_SECONDS)
        delivery.updated_at = datetime.now(UTC)
        db.commit()
        logger.warning(
            "Webhook delivery %s deferred for webhook %s: circuit breaker open.",
            delivery.id,
            webhook.id,
        )
        return

    delivery.attempt_count += 1
    delivery.status = WebhookDeliveryStatus.RETRYING if delivery.attempt_count > 1 else WebhookDeliveryStatus.PENDING
    delivery.updated_at = datetime.now(UTC)
    db.commit()

    with dispatch_limiter.acquire(str(webhook.id)):
        success = _attempt_delivery(delivery, webhook)

    if success:
        delivery.status = WebhookDeliveryStatus.SUCCESS
        delivery.delivered_at = datetime.now(UTC)
        delivery.next_retry_at = None
        logger.info(
            "Webhook delivery %s succeeded on attempt %d for webhook %s.",
            delivery.id,
            delivery.attempt_count,
            webhook.id,
        )
    elif delivery.status == WebhookDeliveryStatus.BREAKER_OPEN:
        pass
    else:
        retry_index = delivery.attempt_count - 1
        max_retries = webhook.max_retries or 3
        retry_delays = _get_retry_delays()

        if retry_index < max_retries and retry_index < len(retry_delays):
            base_delay = retry_delays[retry_index]
            raw_delay = min(base_delay * (2**retry_index), settings.WEBHOOK_RETRY_MAX_DELAY_SECONDS)
            delay = _apply_jitter(raw_delay)
            # Enforce the hard cap after jitter to prevent jitter from exceeding the ceiling
            delay = min(delay, settings.WEBHOOK_RETRY_MAX_DELAY_SECONDS)
            delivery.next_retry_at = datetime.now(UTC) + timedelta(seconds=delay)
            delivery.status = WebhookDeliveryStatus.RETRYING
            logger.warning(
                "Webhook delivery %s failed (attempt %d). Retrying in %ds.",
                delivery.id,
                delivery.attempt_count,
                delay,
            )
        else:
            delivery.status = WebhookDeliveryStatus.DEAD_LETTER
            delivery.dead_lettered_at = datetime.now(UTC)
            delivery.next_retry_at = None
            logger.error(
                "Webhook delivery %s permanently failed after %d attempts. Marked as dead-letter.",
                delivery.id,
                delivery.attempt_count,
            )

    delivery.updated_at = datetime.now(UTC)
    db.commit()


@traced("webhook.trigger_sla_violation")
def trigger_sla_violation_webhooks(
    db: Session,
    sla_data: dict[str, Any],
    event: WebhookEvent = WebhookEvent.SLA_VIOLATION,
    signature_version: int = CURRENT_SIGNATURE_VERSION,
) -> list[WebhookDelivery]:
    """Trigger webhook deliveries for an event with explicit signature versioning (BE-087).

    Args:
        db: Database session
        sla_data: Event data to include in webhook payload
        event: Webhook event type
        signature_version: Signature algorithm version (defaults to current supported version)

    Returns:
        List of created WebhookDelivery records

    Note:
        - Each delivery includes explicit signature_version metadata in headers
        - Timestamp is immutable across retries (idempotency support)
        - Future signing changes can use new version without breaking existing consumers
    """
    webhooks = get_active_webhooks_for_event(db, event)
    deliveries = []

    # Timestamp is captured once and reused across all retries (idempotency support)
    event_timestamp = datetime.now(UTC).isoformat()

    payload = {
        "schema_version": WEBHOOK_SCHEMA_VERSION,
        "event": event.value,
        "timestamp": event_timestamp,
        "data": sla_data,
    }

    celery_available = False
    try:
        from app.tasks.celery_app import celery_app as _celery

        celery_available = not _celery.conf.task_always_eager
    except (ImportError, AttributeError):
        pass

    for webhook in webhooks:
        delivery = create_delivery(
            db,
            webhook,
            event,
            payload,
            signature_version=signature_version,
        )
        deliveries.append(delivery)
        logger.info(
            "Queued webhook delivery %s for webhook %s on event %s (sig_version=%d).",
            delivery.id,
            webhook.id,
            event.value,
            signature_version,
        )

        if celery_available:
            from app.tasks.webhook_tasks import dispatch_webhook_delivery

            dispatch_webhook_delivery.delay(str(delivery.id))
            logger.info("Enqueued webhook delivery %s via Celery.", delivery.id)
        else:
            dispatch_delivery(db, delivery.id)

    return deliveries


def retry_pending_deliveries(db: Session, batch_size: int = WEBHOOK_RETRY_BATCH_SIZE) -> int:
    """Dispatch due retries, capped at `batch_size` per sweep (#299).

    Oldest-due deliveries are processed first; any remainder is picked up by
    the next scheduled sweep rather than blocking this run.
    """
    now = datetime.now(UTC)
    due_deliveries = (
        db.query(WebhookDelivery)
        .filter(
            WebhookDelivery.status.in_(
                [WebhookDeliveryStatus.RETRYING, WebhookDeliveryStatus.BREAKER_OPEN]
            ),
            WebhookDelivery.next_retry_at <= now,
        )
        .order_by(WebhookDelivery.next_retry_at)
        .limit(batch_size)
        .all()
    )

    count = 0
    for delivery in due_deliveries:
        dispatch_delivery(db, delivery.id)
        count += 1

    return count


def get_dead_letter_deliveries(db: Session, webhook_id: UUID | None = None, limit: int = 100) -> list[WebhookDelivery]:
    """Get dead-lettered deliveries for auditing and remediation."""
    query = (
        db.query(WebhookDelivery)
        .filter(WebhookDelivery.status == WebhookDeliveryStatus.DEAD_LETTER)
        .order_by(WebhookDelivery.dead_lettered_at.desc())
    )

    if webhook_id:
        query = query.filter(WebhookDelivery.webhook_id == webhook_id)

    return query.limit(limit).all()


def replay_dead_letter_delivery(db: Session, delivery_id: UUID) -> bool:
    """Replay a dead-lettered delivery by resetting its status and retrying."""
    delivery = db.query(WebhookDelivery).filter(WebhookDelivery.id == delivery_id).first()
    if not delivery:
        logger.error("Dead-letter delivery %s not found.", delivery_id)
        return False

    if delivery.status != WebhookDeliveryStatus.DEAD_LETTER:
        logger.warning("Delivery %s is not in dead-letter status (current: %s).", delivery_id, delivery.status)
        return False

    # Reset delivery state for replay
    delivery.status = WebhookDeliveryStatus.PENDING
    delivery.attempt_count = 0
    delivery.next_retry_at = None
    delivery.dead_lettered_at = None
    delivery.error_message = None
    delivery.response_status_code = None
    delivery.response_body = None
    delivery.delivered_at = None
    delivery.updated_at = datetime.now(UTC)

    db.commit()

    # Dispatch the replay
    dispatch_delivery(db, delivery.id)
    logger.info("Replayed dead-letter delivery %s", delivery_id)
    return True


def replay_deliveries_by_event_context(
    db: Session, event: WebhookEvent, device_id: str | None = None, outage_id: str | None = None, limit: int = 50
) -> int:
    """Replay deliveries by event and context (device or outage)."""
    # Get dead-lettered deliveries matching the criteria
    query = (
        db.query(WebhookDelivery)
        .filter(WebhookDelivery.status == WebhookDeliveryStatus.DEAD_LETTER)
        .filter(WebhookDelivery.event == event)
    )

    # Filter by payload context if provided
    if device_id or outage_id:
        deliveries = query.all()
        matching_deliveries = []

        for delivery in deliveries:
            try:
                payload = json.loads(delivery.payload)
                data = payload.get("data", {})

                if device_id and data.get("device_id") == device_id or outage_id and data.get("outage_id") == outage_id:
                    matching_deliveries.append(delivery)
            except (json.JSONDecodeError, TypeError):
                continue

        deliveries = matching_deliveries[:limit]
    else:
        deliveries = query.limit(limit).all()

    # Replay matching deliveries
    replayed_count = 0
    for delivery in deliveries:
        if replay_dead_letter_delivery(db, delivery.id):
            replayed_count += 1

    logger.info(
        "Replayed %d dead-letter deliveries for event=%s, device_id=%s, outage_id=%s",
        replayed_count,
        event.value,
        device_id,
        outage_id,
    )
    return replayed_count
