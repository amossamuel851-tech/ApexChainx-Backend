"""Encrypt existing webhook secrets at rest (issue #266)

Webhook signing secrets were stored as plaintext, so any database leak
exposed live HMAC keys.  New writes are encrypted by the application via
``app/services/secret_encryption.py``; this migration rewrites existing
plaintext rows so the at-rest guarantee holds for data written before the
change.  It is idempotent (already-encrypted rows are skipped) and a
no-op when ``WEBHOOK_SECRET_ENCRYPTION_KEY`` is not set (local dev).

Revision ID: 0029_encrypt_webhook_secrets
Revises: 0026_jobs_json_columns, 0028_outage_search_trgm
Create Date: 2026-08-27
"""

import logging
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

logger = logging.getLogger(__name__)

# revision identifiers, used by Alembic.
revision: str = "0029_encrypt_webhook_secrets"
down_revision: Union[str, Sequence[str], None] = ("0026_jobs_json_columns", "0028_outage_search_trgm")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _encrypt_plaintext_rows(conn) -> int:
    """Encrypt every plaintext webhook secret; returns the number changed.

    Idempotent: rows already storing Fernet ciphertext are left alone.
    No-op when no encryption key is configured.
    """
    from app.core.config import settings
    from app.services.secret_encryption import encrypt_secret, is_encrypted

    key = settings.WEBHOOK_SECRET_ENCRYPTION_KEY
    if not key:
        logger.warning("WEBHOOK_SECRET_ENCRYPTION_KEY not set; leaving webhook secrets unencrypted")
        return 0

    rows = conn.execute(
        sa.text("SELECT id, secret FROM webhooks WHERE secret IS NOT NULL AND secret != ''")
    ).fetchall()

    changed = 0
    for row_id, secret in rows:
        if secret and not is_encrypted(secret):
            conn.execute(
                sa.text("UPDATE webhooks SET secret = :enc WHERE id = :id"),
                {"enc": encrypt_secret(secret), "id": row_id},
            )
            changed += 1
    if changed:
        logger.info("Encrypted %d plaintext webhook secret(s) at rest", changed)
    return changed


def upgrade() -> None:
    _encrypt_plaintext_rows(op.get_bind())


def downgrade() -> None:
    """Best-effort reverse: decrypt rows back to plaintext when a key exists."""
    from app.core.config import settings
    from app.services.secret_encryption import decrypt_secret, is_encrypted

    key = settings.WEBHOOK_SECRET_ENCRYPTION_KEY
    if not key:
        return

    rows = op.get_bind().execute(
        sa.text("SELECT id, secret FROM webhooks WHERE secret IS NOT NULL AND secret != ''")
    ).fetchall()
    for row_id, secret in rows:
        if secret and is_encrypted(secret):
            plain = decrypt_secret(secret)
            if plain != secret:
                op.get_bind().execute(
                    sa.text("UPDATE webhooks SET secret = :plain WHERE id = :id"),
                    {"plain": plain, "id": row_id},
                )
