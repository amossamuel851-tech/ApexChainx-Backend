import json
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, HttpUrl, field_validator
from sqlalchemy import String, cast, func, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_token, require_admin
from app.db.session import get_db
from app.models.webhook import Webhook, WebhookDelivery, WebhookDeliveryStatus, WebhookEvent

from app.services.audit_log import audit_log
from app.services.formatters import canonical_json
from app.services.secret_encryption import decrypt_secret, encrypt_secret
from app.services.webhook_service import WEBHOOK_SCHEMA_VERSION
from app.utils.network_validation import validate_webhook_url

# Router-level auth (issue #265): every webhook route — including the
# delivery inspection/retry/replay/dead-letter sub-resources — requires an
# admin session.  Previously the sub-resources only depended on the DB
# session, so delivery internals were readable and retry/replay could be
# triggered anonymously.
router = APIRouter(prefix="/webhooks", tags=["Webhooks"], dependencies=[Depends(require_admin)])


# --------------------------------------------------------------------------- #
# Schemas                                                                      #
# --------------------------------------------------------------------------- #


class WebhookCreate(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "outage-webhook",
                "url": "https://example.com/webhook",
                "secret": "supersecret",
                "events": ["sla.violation"],
                "max_retries": 3,
                "is_active": True,
            }
        }
    )

    name: str
    url: HttpUrl
    secret: str | None = None
    events: list[WebhookEvent]
    max_retries: int = 3
    is_active: bool = True

    @field_validator("name")
    @classmethod
    def validate_name_length(cls, v: str) -> str:
        if len(v) > settings.MAX_WEBHOOK_NAME_LENGTH:
            raise ValueError(f"name too long. Maximum length is {settings.MAX_WEBHOOK_NAME_LENGTH} characters.")
        return v

    @field_validator("url")
    @classmethod
    def validate_url_length(cls, v: HttpUrl) -> HttpUrl:
        url_str = str(v)
        if len(url_str) > settings.MAX_WEBHOOK_URL_LENGTH:
            raise ValueError(f"url too long. Maximum length is {settings.MAX_WEBHOOK_URL_LENGTH} characters.")
        validate_webhook_url(url_str)
        return v

    @field_validator("events")
    @classmethod
    def validate_events_count(cls, v: list[WebhookEvent]) -> list[WebhookEvent]:
        if not v:
            raise ValueError("At least one event must be specified.")
        if len(v) > settings.MAX_WEBHOOK_EVENTS_COUNT:
            raise ValueError(f"too many events. Maximum allowed is {settings.MAX_WEBHOOK_EVENTS_COUNT}.")
        return v


class WebhookUpdate(BaseModel):
    name: str | None = None
    url: HttpUrl | None = None
    secret: str | None = None
    events: list[WebhookEvent] | None = None
    max_retries: int | None = None
    is_active: bool | None = None

    @field_validator("name")
    @classmethod
    def validate_name_length(cls, v: str) -> str:
        if v is not None and len(v) > settings.MAX_WEBHOOK_NAME_LENGTH:
            raise ValueError(f"name too long. Maximum length is {settings.MAX_WEBHOOK_NAME_LENGTH} characters.")
        return v

    @field_validator("url")
    @classmethod
    def validate_url_length(cls, v: HttpUrl) -> HttpUrl:
        if v is not None:
            url_str = str(v)
            if len(url_str) > settings.MAX_WEBHOOK_URL_LENGTH:
                raise ValueError(f"url too long. Maximum length is {settings.MAX_WEBHOOK_URL_LENGTH} characters.")
            validate_webhook_url(url_str)
        return v

    @field_validator("events")
    @classmethod
    def validate_events_count(cls, v: list[WebhookEvent]) -> list[WebhookEvent]:
        if v is not None:
            if not v:
                raise ValueError("At least one event must be specified.")
            if len(v) > settings.MAX_WEBHOOK_EVENTS_COUNT:
                raise ValueError(f"too many events. Maximum allowed is {settings.MAX_WEBHOOK_EVENTS_COUNT}.")
        return v


class WebhookResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "outage-webhook",
                "url": "https://example.com/webhook",
                "is_active": True,
                "events": ["sla.violation"],
                "max_retries": 3,
                "schema_version": "1",
            }
        },
        from_attributes=True,
    )

    id: UUID
    name: str
    url: str
    is_active: bool
    events: list[str]
    max_retries: int
    schema_version: str = WEBHOOK_SCHEMA_VERSION  # BE-082: explicit schema version
    # BE-034: Secret lifecycle metadata (without exposing the secret)
    secret_version: int = 1
    last_secret_rotation_at: str | None = None


class WebhookDeliveryResponse(BaseModel):
    id: UUID
    webhook_id: UUID
    event: WebhookEvent
    status: WebhookDeliveryStatus
    attempt_count: int
    response_status_code: int | None
    error_message: str | None
    delivered_at: str | None
    dead_lettered_at: str | None  # BE-086: Include dead-letter timestamp
    signature_version: int  # BE-087: Explicit signature algorithm version
    created_at: str

    model_config = {"from_attributes": True}


class PaginatedWebhookDeliveries(BaseModel):
    items: list[WebhookDeliveryResponse]
    total: int
    offset: int
    limit: int
    returned: int
    has_more: bool


class WebhookSecretRotateResponse(BaseModel):
    webhook_id: UUID
    new_secret: str
    message: str


class WebhookReplayRequest(BaseModel):
    device_id: str | None = None
    outage_id: str | None = None
    limit: int = 50


class WebhookReplayResponse(BaseModel):
    replayed_count: int
    message: str


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _get_webhook_or_404(db: Session, webhook_id: UUID) -> Webhook:
    webhook = db.query(Webhook).filter(Webhook.id == webhook_id).first()
    if not webhook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found.")
    return webhook


def _serialize_webhook(webhook: Webhook) -> WebhookResponse:
    try:
        events = json.loads(webhook.events)
    except (json.JSONDecodeError, TypeError):
        events = []
    return WebhookResponse(
        id=webhook.id,
        name=webhook.name,
        url=webhook.url,
        is_active=webhook.is_active,
        events=events,
        max_retries=webhook.max_retries,
        secret_version=webhook.secret_version,
        last_secret_rotation_at=webhook.last_secret_rotation_at.isoformat()
        if webhook.last_secret_rotation_at
        else None,
    )


def _serialize_delivery(delivery: WebhookDelivery) -> WebhookDeliveryResponse:
    return WebhookDeliveryResponse(
        id=delivery.id,
        webhook_id=delivery.webhook_id,
        event=delivery.event,
        status=delivery.status,
        attempt_count=delivery.attempt_count,
        response_status_code=delivery.response_status_code,
        error_message=delivery.error_message,
        delivered_at=delivery.delivered_at.isoformat() if delivery.delivered_at else None,
        dead_lettered_at=delivery.dead_lettered_at.isoformat() if delivery.dead_lettered_at else None,
        signature_version=delivery.signature_version,
        created_at=delivery.created_at.isoformat(),
    )


# --------------------------------------------------------------------------- #
# Endpoints                                                                    #
# --------------------------------------------------------------------------- #


@router.post("", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
def create_webhook(payload: WebhookCreate, current_user=Depends(require_admin), db: Session = Depends(get_db)):
    url = str(payload.url)
    resolved_ips = validate_webhook_url(url)
    webhook = Webhook(
        name=payload.name,
        url=url,
        # #266: never store the raw signing secret; encrypt at rest.
        secret=encrypt_secret(payload.secret) if payload.secret else None,
        events=canonical_json([e.value for e in payload.events]),
        max_retries=payload.max_retries,
        is_active=payload.is_active,
        resolved_ips=canonical_json(resolved_ips),
    )
    db.add(webhook)
    db.commit()
    db.refresh(webhook)
    return _serialize_webhook(webhook)


@router.get("", response_model=list[WebhookResponse])
def list_webhooks(
    is_active: bool | None = Query(None),
    name: str | None = Query(None, description="Filter by name (case-insensitive substring match)"),  # BE-083
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),  # BE-083
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),  # BE-083
    current_user=Depends(require_admin),
    db: Session = Depends(get_db),
):
    query = db.query(Webhook)
    if is_active is not None:
        query = query.filter(Webhook.is_active == is_active)
    if name:
        query = query.filter(Webhook.name.ilike(f"%{name}%"))
    offset = (page - 1) * page_size
    return [_serialize_webhook(w) for w in query.offset(offset).limit(page_size).all()]


@router.get("/{webhook_id}", response_model=WebhookResponse)
def get_webhook(webhook_id: UUID, current_user=Depends(require_admin), db: Session = Depends(get_db)):
    webhook = _get_webhook_or_404(db, webhook_id)
    return _serialize_webhook(webhook)


@router.patch("/{webhook_id}", response_model=WebhookResponse)
def update_webhook(
    webhook_id: UUID, payload: WebhookUpdate, current_user=Depends(require_admin), db: Session = Depends(get_db)
):
    webhook = _get_webhook_or_404(db, webhook_id)

    if payload.name is not None:
        webhook.name = payload.name
    if payload.url is not None:
        url = str(payload.url)
        resolved_ips = validate_webhook_url(url)
        webhook.url = url
        webhook.resolved_ips = canonical_json(resolved_ips)
    if payload.secret is not None:
        # #266: never store the raw signing secret; encrypt at rest.
        webhook.secret = encrypt_secret(payload.secret)
    if payload.events is not None:
        webhook.events = canonical_json([e.value for e in payload.events])
    if payload.max_retries is not None:
        webhook.max_retries = payload.max_retries
    if payload.is_active is not None:
        webhook.is_active = payload.is_active

    db.commit()
    db.refresh(webhook)
    return _serialize_webhook(webhook)


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(webhook_id: UUID, current_user=Depends(require_admin), db: Session = Depends(get_db)):
    webhook = _get_webhook_or_404(db, webhook_id)
    db.delete(webhook)
    db.commit()


@router.get("/{webhook_id}/deliveries", response_model=PaginatedWebhookDeliveries)
def list_webhook_deliveries(
    webhook_id: UUID,
    status: WebhookDeliveryStatus | None = Query(None, description="Filter by delivery status."),
    event: WebhookEvent | None = Query(None, description="Filter by delivery event type."),
    search: str | None = Query(None, description="Search delivery id, error message, or response status code."),
    created_after: datetime | None = Query(None, description="Return deliveries created after this timestamp."),
    created_before: datetime | None = Query(None, description="Return deliveries created before this timestamp."),
    delivered_after: datetime | None = Query(None, description="Return deliveries delivered after this timestamp."),
    delivered_before: datetime | None = Query(None, description="Return deliveries delivered before this timestamp."),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, description="Number of records to skip"),  # BE-083
    db: Session = Depends(get_db),
):
    _get_webhook_or_404(db, webhook_id)
    query = db.query(WebhookDelivery).filter(WebhookDelivery.webhook_id == webhook_id)

    if status is not None:
        query = query.filter(WebhookDelivery.status == status)
    if event is not None:
        query = query.filter(WebhookDelivery.event == event)
    if created_after is not None:
        query = query.filter(WebhookDelivery.created_at >= created_after)
    if created_before is not None:
        query = query.filter(WebhookDelivery.created_at <= created_before)
    if delivered_after is not None:
        query = query.filter(WebhookDelivery.delivered_at >= delivered_after)
    if delivered_before is not None:
        query = query.filter(WebhookDelivery.delivered_at <= delivered_before)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                cast(WebhookDelivery.id, String).ilike(search_term),
                WebhookDelivery.error_message.ilike(search_term),
                cast(WebhookDelivery.response_status_code, String).ilike(search_term),
            )
        )

    # Single statement for total + page (issue #296): avoids the separate
    # COUNT(*) scan that used to run before every page query. Cursor-based
    # paging (via app/utils/cursor.py) and the composite index are a
    # follow-up that needs a schema migration, tracked in #296.
    paged = (
        query.add_columns(func.count().over().label("total_count"))
        .order_by(WebhookDelivery.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    total = paged[0].total_count if paged else query.order_by(None).count()
    items = [_serialize_delivery(row[0]) for row in paged]
    return PaginatedWebhookDeliveries(
        items=items,
        total=total,
        offset=offset,
        limit=limit,
        returned=len(items),
        has_more=offset + len(items) < total,
    )


@router.post("/{webhook_id}/rotate-secret", response_model=WebhookSecretRotateResponse)  # BE-084
def rotate_webhook_secret(webhook_id: UUID, current_user=Depends(require_admin), db: Session = Depends(get_db)):
    """Rotate the webhook signing secret with a grace period overlap window.

    The previous secret is stored (hashed) and remains valid for WEBHOOK_SECRET_GRACE_HOURS,
    enabling zero-downtime rotation for consumers.

    BE-034: Emits durable audit information with timestamp and actor context.
    """
    from datetime import datetime

    from app.core.config import settings

    webhook = _get_webhook_or_404(db, webhook_id)

    # Capture old metadata for audit trail
    old_secret_version = webhook.secret_version
    old_rotation_time = webhook.last_secret_rotation_at

    # Store old secret in previous_secrets with expiry.  The stored value is
    # encrypted at rest (#266), so hash the *decrypted* secret so the entry
    # stays comparable to the actual signing key.
    current_secret = decrypt_secret(webhook.secret) if webhook.secret else None
    if current_secret:
        now = datetime.now(UTC)
        expires_at = now + timedelta(hours=settings.WEBHOOK_SECRET_GRACE_HOURS)
        previous_entry = {
            "hashed_secret": hash_token(current_secret),
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        if not webhook.previous_secrets:
            webhook.previous_secrets = []
        webhook.previous_secrets.append(previous_entry)

    # Generate new secret and update metadata (encrypted at rest)
    new_secret = secrets.token_hex(32)
    webhook.secret = encrypt_secret(new_secret)
    webhook.secret_version = old_secret_version + 1
    webhook.last_secret_rotation_at = datetime.now(UTC)

    db.commit()

    # Emit audit log with actor context and timestamp
    audit_log.log(
        "webhook_secret_rotated",
        {
            "webhook_id": str(webhook_id),
            "webhook_name": webhook.name,
            "old_secret_version": old_secret_version,
            "new_secret_version": webhook.secret_version,
            "previous_rotation_at": old_rotation_time.isoformat() if old_rotation_time else None,
            "grace_hours": settings.WEBHOOK_SECRET_GRACE_HOURS,
            "rotated_by": getattr(current_user, "email", "unknown"),
        },
    )

    return WebhookSecretRotateResponse(
        webhook_id=webhook.id,
        new_secret=new_secret,
        message=f"Secret rotated. Previous secret will remain valid for {settings.WEBHOOK_SECRET_GRACE_HOURS} hours.",
    )


@router.post("/{webhook_id}/deliveries/{delivery_id}/retry", response_model=WebhookDeliveryResponse)
def retry_delivery(
    webhook_id: UUID, delivery_id: UUID, current_user=Depends(require_admin), db: Session = Depends(get_db)
):
    _get_webhook_or_404(db, webhook_id)
    delivery = (
        db.query(WebhookDelivery)
        .filter(
            WebhookDelivery.id == delivery_id,
            WebhookDelivery.webhook_id == webhook_id,
        )
        .first()
    )
    if not delivery:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found.")
    if delivery.status == WebhookDeliveryStatus.SUCCESS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Delivery already succeeded; retry not needed.",
        )

    from app.services.webhook_service import dispatch_delivery

    dispatch_delivery(db, delivery.id)
    db.refresh(delivery)
    audit_log.log(
        "webhook_delivery_retried",
        {
            "webhook_id": str(webhook_id),
            "delivery_id": str(delivery_id),
            "actor": getattr(current_user, "email", "unknown"),
        },
    )
    return _serialize_delivery(delivery)


# BE-086: Dead-letter handling endpoints


@router.get("/{webhook_id}/dead-letter-deliveries", response_model=list[WebhookDeliveryResponse])
def list_dead_letter_deliveries(
    webhook_id: UUID,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """List dead-lettered deliveries for a webhook."""
    _get_webhook_or_404(db, webhook_id)
    from app.services.webhook_service import get_dead_letter_deliveries

    deliveries = get_dead_letter_deliveries(db, webhook_id=webhook_id, limit=limit)
    return [_serialize_delivery(d) for d in deliveries]


@router.post("/{webhook_id}/deliveries/{delivery_id}/replay", response_model=WebhookDeliveryResponse)
def replay_dead_letter_delivery(
    webhook_id: UUID, delivery_id: UUID, current_user=Depends(require_admin), db: Session = Depends(get_db)
):
    """Replay a dead-lettered delivery."""
    _get_webhook_or_404(db, webhook_id)
    delivery = (
        db.query(WebhookDelivery)
        .filter(
            WebhookDelivery.id == delivery_id,
            WebhookDelivery.webhook_id == webhook_id,
        )
        .first()
    )
    if not delivery:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found.")

    from app.services.webhook_service import replay_dead_letter_delivery

    success = replay_dead_letter_delivery(db, delivery_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to replay delivery. It may not be in dead-letter status.",
        )

    db.refresh(delivery)
    audit_log.log(
        "webhook_dead_letter_replayed",
        {
            "webhook_id": str(webhook_id),
            "delivery_id": str(delivery_id),
            "actor": getattr(current_user, "email", "unknown"),
        },
    )
    return _serialize_delivery(delivery)


# BE-085: Webhook replay by event or outage filters


@router.post("/replay-by-context", response_model=WebhookReplayResponse)
def replay_deliveries_by_context(
    event: WebhookEvent,
    payload: WebhookReplayRequest,
    current_user=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Replay deliveries by event and context (device or outage)."""
    from app.services.webhook_service import replay_deliveries_by_event_context

    replayed_count = replay_deliveries_by_event_context(
        db, event=event, device_id=payload.device_id, outage_id=payload.outage_id, limit=payload.limit
    )

    audit_log.log(
        "webhook_replayed_by_context",
        {
            "event": event.value,
            "device_id": payload.device_id,
            "outage_id": payload.outage_id,
            "limit": payload.limit,
            "replayed_count": replayed_count,
            "actor": getattr(current_user, "email", "unknown"),
        },
    )

    return WebhookReplayResponse(
        replayed_count=replayed_count, message=f"Replayed {replayed_count} deliveries for event {event.value}"
    )
