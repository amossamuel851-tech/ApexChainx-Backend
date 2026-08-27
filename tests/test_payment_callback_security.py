"""Security regression tests for the payment provider callback (issue #264).

The provider callback transitions payment state, so it must be
authenticated and replay-protected even though it is a public integration
surface:

- ``PAYMENT_WEBHOOK_SECRET`` is enforced at startup in non-local
  environments; when it is configured, callbacks without a valid HMAC
  signature are rejected with 401.
- A nonce is mandatory for every callback (400 NONCE_REQUIRED).
- Replay protection lives in Redis so it holds across app workers, not
  just within one process (409 on duplicate nonce).
"""

import hashlib
import hmac
from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models.orm.payment import PaymentTransactionORM
from app.services.single_use_token import SingleUseTokenStore

client = TestClient(app)

CALLBACK_URL = "/api/v1/payments/provider-callback"
TEST_WEBHOOK_SECRET = "test-payment-webhook-secret"


def _sign(transaction_id: str, status: str, nonce: str, secret: str) -> str:
    """Compute the canonical callback HMAC: <transaction_id>:<status>:<nonce>."""
    message = f"{transaction_id}:{status}:{nonce}"
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def _seed_payment(transaction_id: str, status: str = "pending") -> None:
    from app.models.orm.outage import OutageORM

    outage_id = f"outage-{transaction_id}"
    with SessionLocal() as db:
        if db.query(PaymentTransactionORM).filter(PaymentTransactionORM.id == transaction_id).first():
            return
        outage = db.query(OutageORM).filter(OutageORM.id == outage_id).first()
        if not outage:
            outage = OutageORM(
                id=outage_id,
                site_name="Callback Test Site",
                severity="high",
                status="open",
                detected_at=datetime.now(UTC),
                description="Seeded for payment callback security tests",
                affected_services=["core-api"],
            )
            db.add(outage)
        db.add(
            PaymentTransactionORM(
                id=transaction_id,
                transaction_hash=f"tx-{transaction_id}",
                type="reward",
                amount=150.0,
                asset_code="USDC",
                from_address="SYSTEM_POOL",
                to_address="OUTAGE_SETTLEMENT",
                status=status,
                outage_id=outage_id,
                sla_result_id=None,
                created_at=datetime.now(UTC),
                confirmed_at=None,
                retry_count=0,
                last_retried_at=None,
            )
        )
        db.commit()


def _callback_payload(transaction_id: str, status: str = "confirmed", nonce: str | None = None) -> dict:
    payload = {"transaction_id": transaction_id, "status": status}
    if nonce is not None:
        payload["nonce"] = nonce
    return payload


class TestSignatureEnforcement:
    """Callbacks without a valid signature must be rejected when a secret is set."""

    def test_missing_signature_rejected(self, monkeypatch):
        monkeypatch.setattr(settings, "PAYMENT_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
        transaction_id = f"pay_{uuid4().hex[:12]}"
        _seed_payment(transaction_id)
        nonce = uuid4().hex

        resp = client.post(
            CALLBACK_URL,
            json=_callback_payload(transaction_id, nonce=nonce),
            headers={"X-Callback-Nonce": nonce},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Missing webhook signature"

    def test_invalid_signature_rejected(self, monkeypatch):
        monkeypatch.setattr(settings, "PAYMENT_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
        transaction_id = f"pay_{uuid4().hex[:12]}"
        _seed_payment(transaction_id)
        nonce = uuid4().hex

        resp = client.post(
            CALLBACK_URL,
            json=_callback_payload(transaction_id, nonce=nonce),
            headers={"X-Callback-Nonce": nonce, "X-Webhook-Signature": "deadbeef"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid webhook signature"

    def test_valid_signature_accepted(self, monkeypatch):
        monkeypatch.setattr(settings, "PAYMENT_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
        transaction_id = f"pay_{uuid4().hex[:12]}"
        _seed_payment(transaction_id)
        nonce = uuid4().hex
        signature = _sign(transaction_id, "confirmed", nonce, TEST_WEBHOOK_SECRET)

        resp = client.post(
            CALLBACK_URL,
            json=_callback_payload(transaction_id, nonce=nonce),
            headers={"X-Callback-Nonce": nonce, "X-Webhook-Signature": signature},
        )
        assert resp.status_code == 200, resp.json()
        assert resp.json()["status"] == "confirmed"


class TestNonceRequired:
    """A nonce is mandatory on every callback, regardless of signature config."""

    def test_missing_nonce_rejected_with_secret(self, monkeypatch):
        monkeypatch.setattr(settings, "PAYMENT_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
        transaction_id = f"pay_{uuid4().hex[:12]}"
        _seed_payment(transaction_id)
        # Signature computed against an empty nonce so the request would pass
        # signature verification; the nonce check must still reject it.
        signature = _sign(transaction_id, "confirmed", "", TEST_WEBHOOK_SECRET)

        resp = client.post(
            CALLBACK_URL,
            json=_callback_payload(transaction_id),
            headers={"X-Webhook-Signature": signature},
        )
        assert resp.status_code == 400
        assert resp.json()["detail"].startswith("NONCE_REQUIRED")

    def test_missing_nonce_rejected_without_secret(self, monkeypatch):
        monkeypatch.setattr(settings, "PAYMENT_WEBHOOK_SECRET", "")
        transaction_id = f"pay_{uuid4().hex[:12]}"
        _seed_payment(transaction_id)

        resp = client.post(CALLBACK_URL, json=_callback_payload(transaction_id))
        assert resp.status_code == 400
        assert resp.json()["detail"].startswith("NONCE_REQUIRED")


class TestReplayProtection:
    """Duplicate nonces are rejected within the TTL window, across workers."""

    def test_replayed_nonce_rejected_in_same_process(self, monkeypatch):
        monkeypatch.setattr(settings, "PAYMENT_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
        transaction_id = f"pay_{uuid4().hex[:12]}"
        _seed_payment(transaction_id)
        nonce = uuid4().hex
        signature = _sign(transaction_id, "confirmed", nonce, TEST_WEBHOOK_SECRET)
        headers = {"X-Callback-Nonce": nonce, "X-Webhook-Signature": signature}

        first = client.post(CALLBACK_URL, json=_callback_payload(transaction_id, nonce=nonce), headers=headers)
        assert first.status_code == 200, first.json()

        second = client.post(CALLBACK_URL, json=_callback_payload(transaction_id, nonce=nonce), headers=headers)
        assert second.status_code == 409
        assert "replay" in second.json()["detail"].lower()

    def test_replayed_nonce_rejected_from_different_worker(self, monkeypatch):
        """A fresh store instance (new worker) sharing Redis must reject the nonce."""
        monkeypatch.setattr(settings, "PAYMENT_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
        transaction_id = f"pay_{uuid4().hex[:12]}"
        _seed_payment(transaction_id)
        nonce = uuid4().hex
        signature = _sign(transaction_id, "confirmed", nonce, TEST_WEBHOOK_SECRET)
        headers = {"X-Callback-Nonce": nonce, "X-Webhook-Signature": signature}

        first = client.post(CALLBACK_URL, json=_callback_payload(transaction_id, nonce=nonce), headers=headers)
        assert first.status_code == 200, first.json()

        # Simulate a different worker: swap in a brand-new store instance with
        # empty in-process state but the same Redis backend.
        import app.api.v1.endpoints.payments as payments_module

        fresh_store = SingleUseTokenStore(key_prefix="callback_nonce")
        monkeypatch.setattr(payments_module, "nonce_store", fresh_store)

        second = client.post(CALLBACK_URL, json=_callback_payload(transaction_id, nonce=nonce), headers=headers)
        assert second.status_code == 409

    def test_replay_rejected_without_secret(self, monkeypatch):
        """Replay protection does not depend on signature configuration."""
        monkeypatch.setattr(settings, "PAYMENT_WEBHOOK_SECRET", "")
        transaction_id = f"pay_{uuid4().hex[:12]}"
        _seed_payment(transaction_id)
        nonce = uuid4().hex

        first = client.post(CALLBACK_URL, json=_callback_payload(transaction_id, nonce=nonce))
        assert first.status_code == 200, first.json()

        second = client.post(CALLBACK_URL, json=_callback_payload(transaction_id, nonce=nonce))
        assert second.status_code == 409
