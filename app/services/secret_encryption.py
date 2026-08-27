"""Encryption at rest for webhook signing secrets (issue #266).

``Webhook.secret`` is the live HMAC key used to sign outbound webhook
deliveries, so a database leak previously exposed working signing keys as
plaintext.  All writes go through :func:`encrypt_secret` and the raw
secret is only recovered at signing time via :func:`decrypt_secret`,
keyed by ``WEBHOOK_SECRET_ENCRYPTION_KEY`` (a Fernet key).

Local development without a key degrades gracefully (values are stored
as-is); ``validate_critical_settings`` requires the key in non-local
environments so the lax mode can never reach production.  Legacy
plaintext rows (pre-migration) are returned unchanged by
:func:`decrypt_secret` so outbound signing keeps working until the
Alembic migration rewrites them.
"""

import logging

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

logger = logging.getLogger(__name__)

# Fernet ciphertext always starts with this prefix; used to detect
# already-encrypted rows so encryption is idempotent.
_FERNET_PREFIX = "gAAAAA"


def is_valid_fernet_key(key: str) -> bool:
    """Return True if *key* can be used as a Fernet key."""
    try:
        Fernet(key.encode())
        return True
    except (ValueError, TypeError):
        return False


def _fernet() -> Fernet | None:
    key = settings.WEBHOOK_SECRET_ENCRYPTION_KEY
    if not key:
        return None
    return Fernet(key.encode())


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a webhook signing secret for storage.

    Returns Fernet ciphertext, or the value unchanged when no encryption
    key is configured (local development only — the startup validation
    requires the key outside local/test environments).
    """
    fernet = _fernet()
    if fernet is None:
        return plaintext
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(stored: str | None) -> str | None:
    """Recover the plaintext signing secret for *stored*.

    Rows that are not Fernet ciphertext (legacy plaintext written before
    the migration, or dev-only values) are returned unchanged.
    """
    if not stored:
        return stored
    fernet = _fernet()
    if fernet is None:
        return stored
    try:
        return fernet.decrypt(stored.encode()).decode()
    except InvalidToken:
        logger.warning("Stored webhook secret is not valid Fernet ciphertext; returning as-is (pre-migration row?)")
        return stored


def is_encrypted(stored: str) -> bool:
    """Return True if *stored* looks like Fernet ciphertext."""
    return stored.startswith(_FERNET_PREFIX) and len(stored) > 80
