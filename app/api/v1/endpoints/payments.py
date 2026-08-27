import csv
import hashlib
import hmac
import io
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import require_admin, require_engineer
from app.db.session import get_db
from app.models.payment import PaginatedPayments, PaymentTransaction, PaymentTransitionError
from app.repositories.payment_repository import PaymentRepository
from app.services.audit_log import audit_log
from app.services.single_use_token import SingleUseTokenStore
from app.utils.cursor import CursorPage, encode_cursor, decode_cursor

router = APIRouter()

CALLBACK_NONCE_TTL_SECONDS = 300

# BE-028 replay protection: the nonce window must be shared across all app
# workers, not just one process, so it lives in Redis (SET NX EX) with a
# bounded in-process fallback for Redis outages (see single_use_token.py).
nonce_store = SingleUseTokenStore(key_prefix="callback_nonce")


# BE-027: Schemas for reconciliation history
class ReconciliationHistoryEntry(BaseModel):
    """A single reconciliation history entry."""

    event_type: str
    actor: str | None = None
    previous_status: str | None = None
    new_status: str
    timestamp: str
    details: dict[str, Any] | None = None


class ReconciliationHistoryResponse(BaseModel):
    """Payment reconciliation history response."""

    transaction_id: str
    current_status: str
    history: list[ReconciliationHistoryEntry]


# BE-286: whitelisted sort fields/directions, mirroring OutageSortField/
# OutageSortDirection so unknown values 422 instead of being silently ignored.
class PaymentSortField(str, Enum):
    created_at = "created_at"
    amount = "amount"
    status = "status"


class PaymentSortDirection(str, Enum):
    asc = "asc"
    desc = "desc"


@router.get("/")
def list_payments(
    page: int = Query(
        default=1, ge=1, description="Page number (offset pagination). Not used when cursor is provided."
    ),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page."),
    cursor: str | None = Query(
        default=None, description="Cursor for cursor-based pagination. Overrides page/page_size."
    ),
    limit: int = Query(default=20, ge=1, le=100, description="Limit for cursor-based pagination (used with cursor)."),
    status: str | None = None,
    type: str | None = None,
    outage_id: str | None = None,
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    sort_by: PaymentSortField = Query(default=PaymentSortField.created_at),
    sort_dir: PaymentSortDirection = Query(default=PaymentSortDirection.desc),
    current_user=Depends(require_engineer),
    db: Session = Depends(get_db),
):
    """List payments with filtering and pagination.

    Supports both offset-based (page/page_size) and cursor-based (cursor/limit) pagination.
    When ``cursor`` is provided, cursor-based pagination is used; otherwise offset-based.
    """
    if date_from and date_to and date_from > date_to:
        raise HTTPException(status_code=400, detail="date_from cannot be after date_to")
    repo = PaymentRepository(db)

    if cursor is not None:
        return repo.list_cursor(
            cursor=cursor,
            limit=limit,
            status=status,
            outage_id=outage_id,
            type=type,
            date_from=date_from,
            date_to=date_to,
        )

    items, total = repo.list(
        page=page,
        page_size=page_size,
        status=status,
        outage_id=outage_id,
        type=type,
        date_from=date_from,
        date_to=date_to,
        sort_by=sort_by.value,
        sort_dir=sort_dir.value,
    )
    return PaginatedPayments(items=items, total=total, page=page, page_size=page_size)


# BE-287: mirrors GET /outages/export (app/utils/exporter.py conventions) —
# same filters as list_payments, csv/json output, same Content-Disposition
# and 400-on-bad-format behavior. Defined before "/{transaction_id}" so it
# isn't shadowed by that path.
@router.get("/export")
def export_payments(
    format: str = "json",
    status: str | None = None,
    type: str | None = None,
    outage_id: str | None = None,
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    current_user=Depends(require_engineer),
    db: Session = Depends(get_db),
):
    fmt = format.lower()
    if fmt not in ("json", "csv"):
        raise HTTPException(status_code=400, detail="Unsupported export format. Use 'json' or 'csv'.")

    repo = PaymentRepository(db)
    items, _ = repo.list(
        page=1, page_size=10_000, status=status, outage_id=outage_id, type=type, date_from=date_from, date_to=date_to
    )
    rows = [item.model_dump(mode="json") for item in items]

    if fmt == "json":
        return rows

    buffer = io.StringIO()
    fieldnames = list(rows[0].keys()) if rows else ["id", "transaction_hash", "type", "amount", "status"]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=payments.csv"},
    )


@router.get("/ping")
def payments_ping():
    return {"message": "payments ok"}


@router.get("/{transaction_id}/history", response_model=list[dict[str, Any]])
def get_payment_history(transaction_id: str, current_user=Depends(require_engineer), db: Session = Depends(get_db)):
    repo = PaymentRepository(db)
    if not repo.get(transaction_id):
        raise HTTPException(status_code=404, detail="Payment not found")
    return repo.get_payment_history(transaction_id)


@router.get("/{transaction_id}/reconciliation-history", response_model=ReconciliationHistoryResponse)
def get_payment_reconciliation_history(
    transaction_id: str, current_user=Depends(require_engineer), db: Session = Depends(get_db)
):
    """Get detailed reconciliation history for a payment with timestamps and actor context.

    BE-027: Returns a stable, structured history suitable for frontend drawer or audit screen.
    """
    repo = PaymentRepository(db)
    payment = repo.get(transaction_id)
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    history = repo.get_reconciliation_history(transaction_id)

    return ReconciliationHistoryResponse(
        transaction_id=transaction_id,
        current_status=payment.status,
        history=history,
    )


@router.get("/{transaction_id}", response_model=PaymentTransaction)
def get_payment(transaction_id: str, current_user=Depends(require_engineer), db: Session = Depends(get_db)):
    repo = PaymentRepository(db)
    payment = repo.get(transaction_id)
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    return payment


class ReconcileRequest(BaseModel):
    status: str


@router.post("/{transaction_id}/reconcile", response_model=PaymentTransaction)
def reconcile_payment(
    transaction_id: str, payload: ReconcileRequest, current_user=Depends(require_admin), db: Session = Depends(get_db)
):
    repo = PaymentRepository(db)
    existing = repo.get(transaction_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Payment not found")

    try:
        payment = repo.reconcile(transaction_id, payload.status)
    except PaymentTransitionError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "message": str(exc),
                "current_status": exc.current,
                "requested_status": exc.next_status,
                "allowed_transitions": list(exc.allowed),
            },
        )
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    # BE-027: Include previous status in audit log for reconciliation history
    audit_log.log(
        "payment_reconciled",
        {
            "id": transaction_id,
            "previous_status": existing.status,
            "status": payload.status,
        },
    )
    return payment


@router.post("/{transaction_id}/retry", response_model=PaymentTransaction)
def retry_payment(transaction_id: str, current_user=Depends(require_engineer), db: Session = Depends(get_db)):
    repo = PaymentRepository(db)
    existing = repo.get(transaction_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Payment not found")
    try:
        payment = repo.retry(transaction_id)
    except PaymentTransitionError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "message": str(exc),
                "current_status": exc.current,
                "requested_status": exc.next_status,
                "allowed_transitions": list(exc.allowed),
            },
        )
    if not payment:
        raise HTTPException(status_code=409, detail="Max retries reached")
    audit_log.log(
        "payment_retried",
        {"id": transaction_id, "retry_count": payment.retry_count, "override": False},
    )
    return payment


# ---------------------------------------------------------------------------
# Retry queue with backoff visibility (#240)
# ---------------------------------------------------------------------------

# Exponential backoff: base 30s, doubles each attempt, capped at 1 hour.
_RETRY_BASE_SECONDS = 30
_RETRY_MAX_SECONDS = 3600


def _compute_next_retry_at(retry_count: int, last_retried_at: datetime | None) -> datetime | None:
    """Return the datetime when the next retry should occur, or None if at max."""
    if retry_count >= PaymentRepository.MAX_RETRIES:
        return None
    delay = min(_RETRY_BASE_SECONDS * (2**retry_count), _RETRY_MAX_SECONDS)
    anchor = last_retried_at or datetime.now(UTC)
    return anchor + timedelta(seconds=delay)


class PaymentRetryQueueItem(BaseModel):
    """A payment in the retry queue with backoff metadata."""

    id: str
    transaction_hash: str
    type: str
    amount: float
    status: str
    outage_id: str
    attempt_count: int
    next_retry_at: datetime | None
    backoff_seconds: int
    created_at: datetime
    last_retried_at: datetime | None


@router.get("/retry-queue", response_model=CursorPage)
def list_retry_queue(
    cursor: str | None = Query(default=None, description="Cursor for pagination."),
    limit: int = Query(default=20, ge=1, le=100, description="Max items per page."),
    current_user=Depends(require_engineer),
    db: Session = Depends(get_db),
):
    """Return payments eligible for retry with computed backoff metadata.

    Supports cursor-based pagination. The cursor encodes
    ``(created_at, id)`` of the last item on the previous page.
    """
    repo = PaymentRepository(db)
    items, _ = repo.list(status="failed")

    decoded = decode_cursor(cursor)
    if decoded is not None:
        cursor_id, cursor_created_at_str = decoded
        items = [p for p in items if (p.created_at.isoformat(), p.id) < (cursor_created_at_str, cursor_id)]

    page_items = items[:limit]
    has_more = len(items) > limit

    result: list[PaymentRetryQueueItem] = []
    for p in page_items:
        next_at = _compute_next_retry_at(p.retry_count, p.last_retried_at)
        backoff = min(_RETRY_BASE_SECONDS * (2**p.retry_count), _RETRY_MAX_SECONDS)
        result.append(
            PaymentRetryQueueItem(
                id=p.id,
                transaction_hash=p.transaction_hash,
                type=p.type,
                amount=p.amount,
                status=p.status,
                outage_id=p.outage_id,
                attempt_count=p.retry_count,
                next_retry_at=next_at,
                backoff_seconds=backoff,
                created_at=p.created_at,
                last_retried_at=p.last_retried_at,
            )
        )

    next_cursor = None
    if has_more and result:
        last = result[-1]
        next_cursor = encode_cursor(last.id, last.created_at.isoformat())

    return CursorPage(items=result, next_cursor=next_cursor, has_more=has_more)


@router.post("/retry-queue/{transaction_id}/retry", response_model=PaymentTransaction)
def retry_now(
    transaction_id: str,
    current_user=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Admin endpoint: trigger an immediate retry, bypassing exponential backoff."""
    repo = PaymentRepository(db)
    existing = repo.get(transaction_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Payment not found")
    try:
        payment = repo.retry(transaction_id)
    except PaymentTransitionError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "message": str(exc),
                "current_status": exc.current,
                "requested_status": exc.next_status,
                "allowed_transitions": list(exc.allowed),
            },
        )
    if not payment:
        raise HTTPException(status_code=409, detail="Max retries reached")
    audit_log.log(
        "payment_retried",
        {
            "id": transaction_id,
            "retry_count": payment.retry_count,
            "actor": current_user.email,
            "override": True,
        },
    )
    return payment


class ProviderCallbackRequest(BaseModel):
    transaction_id: str
    status: str
    provider_ref: str | None = None
    # BE-028: callers must supply a per-request nonce for replay protection.
    # The nonce must be unique within the CALLBACK_NONCE_TTL_SECONDS window.
    nonce: str | None = None


def _verify_callback_signature(
    transaction_id: str,
    status: str,
    nonce: str | None,
    signature: str,
    secret: str,
) -> bool:
    """HMAC-SHA256 verification.

    Canonical message: ``<transaction_id>:<status>:<nonce>``
    Including the nonce in the signed payload binds the signature to this
    specific request so that replaying a captured (signature, payload) pair
    against a different nonce produces a different expected signature.
    """
    message = f"{transaction_id}:{status}:{nonce or ''}"
    expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/provider-callback", response_model=PaymentTransaction)
def provider_callback(
    payload: ProviderCallbackRequest,
    x_webhook_signature: str | None = Header(default=None),
    x_callback_nonce: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    """
    Inbound callback from a payment provider to update payment status (BE-028).

    Security model (signature now required):
    - HMAC-SHA256 signature (X-Webhook-Signature) is verified against
      PAYMENT_WEBHOOK_SECRET, which must be configured in non-local
      environments (enforced at startup by validate_critical_settings).
      The signed message is ``<transaction_id>:<status>:<nonce>`` so
      replaying a captured request fails if the nonce changes.
    - A nonce is REQUIRED for every callback (X-Callback-Nonce header or
      the ``nonce`` body field).  Callbacks without one are rejected with
      400 and error code ``NONCE_REQUIRED``.
    - Replay protection: the nonce must be unique within the
      CALLBACK_NONCE_TTL_SECONDS window.  The window is enforced in Redis
      (shared across all app workers); duplicate nonces are rejected with
      409 Conflict.
    - Idempotency: a callback that moves a payment into its current status
      is silently accepted (returns 200 with the unchanged record).
    - Failures and suspicious events are written to the audit log so they
      are reviewable later.
    """
    # --- 1. Resolve nonce (header takes precedence over body field) ----------
    effective_nonce = x_callback_nonce or payload.nonce

    # --- 2. Nonce is mandatory (replay protection requires it) ---------------
    if not effective_nonce:
        audit_log.log(
            "callback_rejected_missing_nonce",
            {"transaction_id": payload.transaction_id, "provider_ref": payload.provider_ref},
        )
        raise HTTPException(
            status_code=400,
            detail="NONCE_REQUIRED: callback nonce is required for replay protection",
        )

    # --- 3. Authenticate signature -------------------------------------------
    secret = settings.PAYMENT_WEBHOOK_SECRET
    if secret:
        if not x_webhook_signature:
            audit_log.log(
                "callback_rejected_missing_signature",
                {"transaction_id": payload.transaction_id, "provider_ref": payload.provider_ref},
            )
            raise HTTPException(status_code=401, detail="Missing webhook signature")

        if not _verify_callback_signature(
            payload.transaction_id,
            payload.status,
            effective_nonce,
            x_webhook_signature,
            secret,
        ):
            audit_log.log(
                "callback_rejected_bad_signature",
                {"transaction_id": payload.transaction_id, "provider_ref": payload.provider_ref},
            )
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # --- 4. Replay protection (shared across workers via Redis) --------------
    if not nonce_store.consume(effective_nonce, CALLBACK_NONCE_TTL_SECONDS):
        audit_log.log(
            "callback_rejected_replay",
            {
                "transaction_id": payload.transaction_id,
                "nonce": effective_nonce,
                "provider_ref": payload.provider_ref,
            },
        )
        raise HTTPException(
            status_code=409,
            detail="Duplicate callback nonce – possible replay attack",
        )

    repo = PaymentRepository(db)
    existing = repo.get(payload.transaction_id)
    if not existing:
        audit_log.log(
            "callback_rejected_unknown_payment",
            {"transaction_id": payload.transaction_id, "provider_ref": payload.provider_ref},
        )
        raise HTTPException(status_code=404, detail="Payment not found")

    if existing.status == payload.status:
        audit_log.log(
            "payment_provider_callback_duplicate",
            {
                "transaction_id": payload.transaction_id,
                "provider_ref": payload.provider_ref,
                "nonce": effective_nonce,
                "status": payload.status,
            },
        )
        return existing

    try:
        updated = repo.reconcile(payload.transaction_id, payload.status)
    except (ValueError, PaymentTransitionError) as exc:
        audit_log.log(
            "callback_rejected_invalid_transition",
            {
                "transaction_id": payload.transaction_id,
                "from_status": existing.status,
                "to_status": payload.status,
                "provider_ref": payload.provider_ref,
                "error": str(exc),
            },
        )
        audit_log.log(
            "payment_dead_letter",
            {
                "transaction_id": payload.transaction_id,
                "from_status": existing.status,
                "to_status": payload.status,
                "provider_ref": payload.provider_ref,
                "error": str(exc),
                "error_type": type(exc).__name__,
            },
        )
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        audit_log.log(
            "payment_dead_letter",
            {
                "transaction_id": payload.transaction_id,
                "from_status": existing.status,
                "to_status": payload.status,
                "provider_ref": payload.provider_ref,
                "error": str(exc),
                "error_type": type(exc).__name__,
            },
        )
        raise HTTPException(status_code=500, detail="Internal error processing callback")

    audit_log.log(
        "payment_provider_callback",
        {
            "id": payload.transaction_id,
            "status": payload.status,
            "provider_ref": payload.provider_ref,
            "nonce": effective_nonce,
        },
    )

    # Auto-retry on failure: if the provider marked the payment as failed
    # and we have retries remaining, schedule a retry with exponential backoff.
    if payload.status == "failed" and updated.retry_count < PaymentRepository.MAX_RETRIES:
        payment = repo.retry(payload.transaction_id)
        if payment:
            next_retry_at = _compute_next_retry_at(payment.retry_count, payment.last_retried_at)
            audit_log.log(
                "payment_auto_retry_scheduled",
                {
                    "id": payload.transaction_id,
                    "retry_count": payment.retry_count,
                    "next_retry_at": next_retry_at.isoformat() if next_retry_at else None,
                },
            )

    return updated
