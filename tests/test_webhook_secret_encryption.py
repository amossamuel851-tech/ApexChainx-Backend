"""Tests for encryption at rest of webhook signing secrets (issue #266).

``Webhook.secret`` is the live HMAC key for outbound deliveries, so it
must not sit in the database as recoverable plaintext.  All writes go
through ``encrypt_secret``, signing decrypts at the last moment, and the
Alembic migration rewrites legacy plaintext rows idempotently.
"""

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.config import settings
from app.core.security import get_password_hash, hash_token
from app.db.session import SessionLocal
from app.main import app
from app.models.enums import Role
from app.models.webhook import Webhook
from app.repositories.user_repository import UserRepository
from app.services.formatters import canonical_json
from app.services.secret_encryption import (
    decrypt_secret,
    encrypt_secret,
    is_encrypted,
    is_valid_fernet_key,
)
from app.services.webhook_signing import sign_payload_v1

client = TestClient(app)

ADMIN_EMAIL = "secret_admin@example.com"
TEST_FERNET_KEY = Fernet.generate_key().decode()
PLAINTEXT_SECRET = "supersecret-webhook-key"


@pytest.fixture(autouse=True)
def _encryption_key(monkeypatch):
    monkeypatch.setattr(settings, "WEBHOOK_SECRET_ENCRYPTION_KEY", TEST_FERNET_KEY)
    yield


@pytest.fixture(scope="module")
def admin_token():
    from uuid import uuid4 as _uuid4

    with SessionLocal() as db:
        repo = UserRepository(db)
        if not repo.get_by_email(ADMIN_EMAIL):
            repo.create(
                user_id=f"user_{_uuid4().hex[:8]}",
                email=ADMIN_EMAIL,
                hashed_password=get_password_hash("Admin123!"),
                full_name="Secret Admin",
                role=Role.admin,
            )
    resp = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": "Admin123!"})
    assert resp.status_code == 200, resp.json()
    return resp.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _db_secret(webhook_id: str) -> str | None:
    with SessionLocal() as db:
        return db.execute(text("SELECT secret FROM webhooks WHERE id = :id"), {"id": webhook_id}).scalar()


class TestEncryptionService:
    def test_encrypt_decrypt_roundtrip(self):
        encrypted = encrypt_secret(PLAINTEXT_SECRET)
        assert encrypted != PLAINTEXT_SECRET
        assert is_encrypted(encrypted)
        assert decrypt_secret(encrypted) == PLAINTEXT_SECRET

    def test_encrypt_returns_plaintext_without_key(self, monkeypatch):
        monkeypatch.setattr(settings, "WEBHOOK_SECRET_ENCRYPTION_KEY", "")
        assert encrypt_secret(PLAINTEXT_SECRET) == PLAINTEXT_SECRET
        assert decrypt_secret(PLAINTEXT_SECRET) == PLAINTEXT_SECRET

    def test_decrypt_legacy_plaintext_row_returns_as_is(self):
        # A row written before encryption must not break outbound signing.
        assert decrypt_secret("legacy-plaintext") == "legacy-plaintext"

    def test_is_encrypted_rejects_plaintext(self):
        assert is_encrypted(PLAINTEXT_SECRET) is False

    def test_valid_fernet_key_accepted_and_garbage_rejected(self):
        assert is_valid_fernet_key(TEST_FERNET_KEY) is True
        assert is_valid_fernet_key("not-a-fernet-key") is False
        assert is_valid_fernet_key("") is False


class TestStorageEncryption:
    def test_create_webhook_does_not_store_raw_secret(self, admin_token):
        resp = client.post(
            "/api/v1/webhooks",
            json={
                "name": "encrypted-hook",
                "url": "https://example.com/webhook",
                "secret": PLAINTEXT_SECRET,
                "events": ["sla.violation"],
            },
            headers=_auth(admin_token),
        )
        assert resp.status_code == 201, resp.json()
        webhook_id = str(resp.json()["id"])
        stored = _db_secret(webhook_id)
        assert stored is not None
        assert PLAINTEXT_SECRET not in stored
        assert is_encrypted(stored)
        # The plaintext is only recoverable at signing time.
        assert decrypt_secret(stored) == PLAINTEXT_SECRET

    def test_update_webhook_encrypts_new_secret(self, admin_token):
        resp = client.post(
            "/api/v1/webhooks",
            json={
                "name": "encrypted-update-hook",
                "url": "https://example.com/webhook",
                "secret": "first-secret",
                "events": ["sla.violation"],
            },
            headers=_auth(admin_token),
        )
        webhook_id = str(resp.json()["id"])

        resp = client.patch(
            f"/api/v1/webhooks/{webhook_id}",
            json={"secret": PLAINTEXT_SECRET},
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200, resp.json()
        stored = _db_secret(webhook_id)
        assert PLAINTEXT_SECRET not in stored
        assert is_encrypted(stored)

    def test_rotate_webhook_secret_encrypts_new_and_hashes_old(self, admin_token):
        resp = client.post(
            "/api/v1/webhooks",
            json={
                "name": "encrypted-rotate-hook",
                "url": "https://example.com/webhook",
                "secret": "old-secret",
                "events": ["sla.violation"],
            },
            headers=_auth(admin_token),
        )
        webhook_id = str(resp.json()["id"])

        resp = client.post(
            f"/api/v1/webhooks/{webhook_id}/rotate-secret",
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200, resp.json()
        new_secret = resp.json()["new_secret"]

        with SessionLocal() as db:
            row = db.execute(
                text("SELECT secret, previous_secrets FROM webhooks WHERE id = :id"),
                {"id": webhook_id},
            ).one()
        stored, previous_secrets = row
        # New secret is encrypted at rest and returned in plaintext once.
        assert new_secret not in stored
        assert is_encrypted(stored)
        assert decrypt_secret(stored) == new_secret
        # Previous entry hashes the *decrypted* old secret so it stays
        # comparable to the actual signing key.  JSONB columns come back as
        # already-parsed lists from psycopg2.
        entry = previous_secrets[0]
        assert entry["hashed_secret"] == hash_token("old-secret")


class TestSigningStillWorks:
    def test_build_headers_signs_with_decrypted_secret(self):
        from app.services.webhook_service import _build_headers

        webhook = Webhook(
            id=str(uuid4()),
            name="signing-hook",
            url="https://example.com/webhook",
            secret=encrypt_secret(PLAINTEXT_SECRET),
            is_active=True,
            events=canonical_json(["sla.violation"]),
        )
        payload = '{"event": "sla.violation", "ts": "2026-08-27T00:00:00"}'
        headers = _build_headers(webhook, payload)

        signature = headers["X-Webhook-Signature"]
        assert signature.startswith("sha256=")
        digest = signature.removeprefix("sha256=")
        assert digest == sign_payload_v1(PLAINTEXT_SECRET, payload)


class TestMigrationEncryptsLegacyRows:
    def test_encrypts_plaintext_rows_idempotently(self):
        # alembic/versions is not an importable package, so load by path.
        path = Path("alembic/versions/0029_encrypt_webhook_secrets.py")
        spec = importlib.util.spec_from_file_location("migration_0029_encrypt", path)
        mig = importlib.util.module_from_spec(spec)
        assert spec is not None and spec.loader is not None
        spec.loader.exec_module(mig)
        webhook_id = str(uuid4())

        with SessionLocal() as db:
            db.execute(
                text(
                    "INSERT INTO webhooks "
                    "(id, name, url, secret, is_active, events, max_retries, previous_secrets, secret_version, "
                    "secret_grace_hours, created_at, updated_at) "
                    "VALUES (:id, :name, :url, :secret, true, :events, 3, '[]', 1, 24, now(), now())"
                ),
                {
                    "id": webhook_id,
                    "name": "legacy-hook",
                    "url": "https://example.com/webhook",
                    "secret": "legacy-plaintext-secret",
                    "events": '["sla.violation"]',
                },
            )
            db.commit()

        with SessionLocal() as db:
            changed = mig._encrypt_plaintext_rows(db.connection())
            db.commit()
            assert changed == 1
            stored = db.execute(
                text("SELECT secret FROM webhooks WHERE id = :id"), {"id": webhook_id}
            ).scalar()
            assert stored != "legacy-plaintext-secret"
            assert is_encrypted(stored)
            assert decrypt_secret(stored) == "legacy-plaintext-secret"

        # Idempotent: a second pass changes nothing and does not error.
        with SessionLocal() as db:
            changed_again = mig._encrypt_plaintext_rows(db.connection())
            db.commit()
            assert changed_again == 0
