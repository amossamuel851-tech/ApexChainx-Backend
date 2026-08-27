"""Auth regression tests for webhook delivery sub-resources (issue #265).

The webhook delivery inspection, retry, replay and dead-letter endpoints
previously declared no authentication dependency, so delivery internals
(error messages, response metadata) were readable and retry/replay actions
could be triggered anonymously.  All webhook routes now require an admin
session at the router level, and retry/replay actions audit the acting
admin's identity.
"""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.security import get_password_hash
from app.db.session import SessionLocal
from app.main import app
from app.models.enums import Role
from app.repositories.user_repository import UserRepository

client = TestClient(app)

ADMIN_EMAIL = "webhook_admin@example.com"
ENGINEER_EMAIL = "webhook_engineer@example.com"


def _ensure_user(email: str, role: Role, password: str) -> None:
    with SessionLocal() as db:
        repo = UserRepository(db)
        if not repo.get_by_email(email):
            from uuid import uuid4 as _uuid4

            repo.create(
                user_id=f"user_{_uuid4().hex[:8]}",
                email=email,
                hashed_password=get_password_hash(password),
                full_name="Webhook Test User",
                role=role,
            )


def _login(email: str, password: str) -> str:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.json()
    return resp.json()["access_token"]


@pytest.fixture(scope="module")
def admin_token() -> str:
    _ensure_user(ADMIN_EMAIL, Role.admin, "Admin123!")
    return _login(ADMIN_EMAIL, "Admin123!")


@pytest.fixture(scope="module")
def engineer_token() -> str:
    _ensure_user(ENGINEER_EMAIL, Role.engineer, "Engineer123!")
    return _login(ENGINEER_EMAIL, "Engineer123!")


def _seed_webhook_and_delivery() -> tuple[str, str]:
    """Create a webhook with one failed delivery; returns (webhook_id, delivery_id).

    Uses raw SQL for the delivery row so the test never depends on the
    webhook creation endpoints.
    """
    webhook_id = str(uuid4())
    delivery_id = str(uuid4())
    with SessionLocal() as db:
        db.execute(
            text(
                "INSERT INTO webhooks "
                "(id, name, url, secret, is_active, events, max_retries, previous_secrets, secret_version, secret_grace_hours, created_at, updated_at) "
                "VALUES (:id, :name, :url, NULL, true, :events, 3, '[]', 1, 24, now(), now())"
            ),
            {"id": webhook_id, "name": "auth-test-hook", "url": "https://example.com/webhook", "events": '[\"sla.violation\"]'},
        )
        db.execute(
            text(
                "INSERT INTO webhook_deliveries "
                "(id, webhook_id, event, payload, status, attempt_count, error_message, signature_version, created_at, updated_at) "
                "VALUES (:id, :webhook_id, 'SLA_VIOLATION', '{}', 'FAILED', 1, 'Request error: boom', 1, now(), now())"
            ),
            {"id": delivery_id, "webhook_id": webhook_id},
        )
        db.commit()
    return webhook_id, delivery_id


class TestDeliveryEndpointsRequireAuth:
    """Every previously-unauthenticated webhook sub-resource must return 401."""

    def test_list_deliveries_requires_auth(self):
        webhook_id, _ = _seed_webhook_and_delivery()
        resp = client.get(f"/api/v1/webhooks/{webhook_id}/deliveries")
        assert resp.status_code == 401

    def test_retry_delivery_requires_auth(self):
        webhook_id, delivery_id = _seed_webhook_and_delivery()
        resp = client.post(f"/api/v1/webhooks/{webhook_id}/deliveries/{delivery_id}/retry")
        assert resp.status_code == 401

    def test_list_dead_letter_deliveries_requires_auth(self):
        webhook_id, _ = _seed_webhook_and_delivery()
        resp = client.get(f"/api/v1/webhooks/{webhook_id}/dead-letter-deliveries")
        assert resp.status_code == 401

    def test_replay_dead_letter_delivery_requires_auth(self):
        webhook_id, delivery_id = _seed_webhook_and_delivery()
        resp = client.post(f"/api/v1/webhooks/{webhook_id}/deliveries/{delivery_id}/replay")
        assert resp.status_code == 401

    def test_replay_by_context_requires_auth(self):
        resp = client.post("/api/v1/webhooks/replay-by-context?event=sla.violation", json={})
        assert resp.status_code == 401


class TestDeliveryEndpointsRejectNonAdmin:
    """Engineers (authenticated, non-admin) must be rejected with 403."""

    def test_list_deliveries_forbidden_for_engineer(self, engineer_token):
        webhook_id, _ = _seed_webhook_and_delivery()
        resp = client.get(
            f"/api/v1/webhooks/{webhook_id}/deliveries",
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert resp.status_code == 403

    def test_retry_delivery_forbidden_for_engineer(self, engineer_token):
        webhook_id, delivery_id = _seed_webhook_and_delivery()
        resp = client.post(
            f"/api/v1/webhooks/{webhook_id}/deliveries/{delivery_id}/retry",
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert resp.status_code == 403

    def test_replay_by_context_forbidden_for_engineer(self, engineer_token):
        resp = client.post(
            "/api/v1/webhooks/replay-by-context?event=sla.violation",
            json={},
            headers={"Authorization": f"Bearer {engineer_token}"},
        )
        assert resp.status_code == 403


class TestRetryAndReplayAuditActor:
    """Retry/replay actions must audit-log the acting admin's identity."""

    def test_retry_delivery_audits_admin_actor(self, admin_token, monkeypatch):
        import app.api.v1.endpoints.webhooks as webhooks_module

        recorded = []

        class FakeAuditLog:
            @staticmethod
            def log(event_type, details=None):
                recorded.append((event_type, details or {}))

        monkeypatch.setattr(webhooks_module, "audit_log", FakeAuditLog())
        monkeypatch.setattr("app.services.webhook_service.dispatch_delivery", lambda db, delivery_id: None)

        webhook_id, delivery_id = _seed_webhook_and_delivery()
        resp = client.post(
            f"/api/v1/webhooks/{webhook_id}/deliveries/{delivery_id}/retry",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200, resp.json()

        events = [e for e, _ in recorded if e == "webhook_delivery_retried"]
        assert events, "expected a webhook_delivery_retried audit entry"
        details = [d for e, d in recorded if e == "webhook_delivery_retried"][0]
        assert details["actor"] == ADMIN_EMAIL
        assert details["delivery_id"] == delivery_id

    def test_replay_dead_letter_audits_admin_actor(self, admin_token, monkeypatch):
        import app.api.v1.endpoints.webhooks as webhooks_module

        recorded = []

        class FakeAuditLog:
            @staticmethod
            def log(event_type, details=None):
                recorded.append((event_type, details or {}))

        monkeypatch.setattr(webhooks_module, "audit_log", FakeAuditLog())
        monkeypatch.setattr("app.services.webhook_service.replay_dead_letter_delivery", lambda db, delivery_id: True)

        webhook_id, delivery_id = _seed_webhook_and_delivery()
        resp = client.post(
            f"/api/v1/webhooks/{webhook_id}/deliveries/{delivery_id}/replay",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200, resp.json()

        details = [d for e, d in recorded if e == "webhook_dead_letter_replayed"][0]
        assert details["actor"] == ADMIN_EMAIL

    def test_replay_by_context_audits_admin_actor(self, admin_token, monkeypatch):
        import app.api.v1.endpoints.webhooks as webhooks_module

        recorded = []

        class FakeAuditLog:
            @staticmethod
            def log(event_type, details=None):
                recorded.append((event_type, details or {}))

        monkeypatch.setattr(webhooks_module, "audit_log", FakeAuditLog())
        monkeypatch.setattr(
            "app.services.webhook_service.replay_deliveries_by_event_context",
            lambda db, event, device_id=None, outage_id=None, limit=50: 3,
        )

        resp = client.post(
            "/api/v1/webhooks/replay-by-context?event=sla.violation",
            json={"outage_id": "outage-123", "limit": 10},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200, resp.json()

        details = [d for e, d in recorded if e == "webhook_replayed_by_context"][0]
        assert details["actor"] == ADMIN_EMAIL
        assert details["outage_id"] == "outage-123"
        assert details["replayed_count"] == 3
