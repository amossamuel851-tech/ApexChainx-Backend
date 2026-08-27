from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_password_hash, hash_token, validate_password_policy, verify_password
from app.db.session import SessionLocal
from app.models.auth import AuthSessionResponse, AuthUser, LoginRequest, RegisterRequest
from app.models.enums import Role
from app.repositories.session_repository import SessionRepository
from app.repositories.token_family_repository import TokenFamilyRepository
from app.repositories.user_repository import UserRepository, user_orm_to_pydantic
from app.services.audit_log import audit_log

TOKEN_TTL_SECONDS = 3600


class AuthStore:
    @staticmethod
    def _now() -> datetime:
        return datetime.now(UTC)

    @staticmethod
    def _is_expired(expires_at: datetime, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        else:
            current = current.astimezone(UTC)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        else:
            expires_at = expires_at.astimezone(UTC)
        return current > expires_at

    @classmethod
    def register(cls, payload: RegisterRequest, db: Session = None) -> AuthUser:
        if db is None:
            with SessionLocal() as db:
                return cls._register_with_db(payload, db)
        return cls._register_with_db(payload, db)

    @classmethod
    def _register_with_db(cls, payload: RegisterRequest, db: Session) -> AuthUser:
        user_repo = UserRepository(db)
        if user_repo.get_by_email(payload.email):
            raise ValueError("User already exists")

        if not validate_password_policy(payload.password):
            raise ValueError(
                "Password does not meet policy requirements (min 8 chars, " "uppercase, lowercase, digit, special char)"
            )

        hashed_password = get_password_hash(payload.password)
        user_id = f"user_{uuid4().hex[:8]}"

        orm_user = user_repo.create(
            user_id=user_id,
            email=payload.email,
            hashed_password=hashed_password,
            full_name=payload.full_name,
            role=Role.engineer,
        )

        audit_log.log_event(
            db,
            "registration",
            email=payload.email,
            actor_id=user_id,
            details={"user_id": user_id, "role": Role.engineer},
        )

        return user_orm_to_pydantic(orm_user)

    @classmethod
    def admin_create_user(cls, email: str, password: str, full_name: str, role: Role, actor_id: str, actor_email: str, db: Session) -> AuthUser:
        """Admin-only user creation with audit logging of the approving admin."""
        user_repo = UserRepository(db)
        if user_repo.get_by_email(email):
            raise ValueError("User already exists")

        if not validate_password_policy(password):
            raise ValueError(
                "Password does not meet policy requirements (min 8 chars, "
                "uppercase, lowercase, digit, special char)"
            )

        hashed_password = get_password_hash(password)
        user_id = f"user_{uuid4().hex[:8]}"

        orm_user = user_repo.create(
            user_id=user_id,
            email=email,
            hashed_password=hashed_password,
            full_name=full_name,
            role=role,
        )

        audit_log.log_event(
            db,
            "admin_user_created",
            email=actor_email,
            actor_id=actor_id,
            details={"created_user_id": user_id, "created_email": email, "role": role},
        )

        return user_orm_to_pydantic(orm_user)

    @classmethod
    def login(cls, payload: LoginRequest, db: Session = None) -> AuthSessionResponse:
        if db is None:
            with SessionLocal() as db:
                return cls._login_with_db(payload, db)
        return cls._login_with_db(payload, db)

    @classmethod
    def _login_with_db(cls, payload: LoginRequest, db: Session) -> AuthSessionResponse:
        user_repo = UserRepository(db)
        session_repo = SessionRepository(db)

        # Check if account is locked
        if user_repo.is_account_locked(payload.email):
            audit_log.log_event(db, "login_failed_locked", email=payload.email, details={"reason": "account_locked"})
            raise ValueError("Account is temporarily locked due to too many failed login attempts")

        stored_user = user_repo.get_by_email(payload.email)
        if not stored_user or not verify_password(payload.password, stored_user.hashed_password):
            # Increment failed attempts
            user_repo.increment_failed_attempts(payload.email)

            # Check if we need to lock the account
            if stored_user and (stored_user.failed_login_attempts or 0) >= settings.AUTH_MAX_FAILED_ATTEMPTS:
                lockout_until = cls._now() + timedelta(minutes=settings.AUTH_LOCKOUT_DURATION_MINUTES)
                user_repo.lock_account(payload.email, lockout_until)
                audit_log.log_event(
                    db,
                    "account_locked",
                    email=payload.email,
                    actor_id=stored_user.user_id,
                    details={
                        "lockout_duration_minutes": settings.AUTH_LOCKOUT_DURATION_MINUTES,
                        "failed_attempts": stored_user.failed_login_attempts,
                    },
                )
                raise ValueError(
                    f"Account locked due to too many failed attempts. Try again in {settings.AUTH_LOCKOUT_DURATION_MINUTES} minutes"
                )

            audit_log.log_event(
                db,
                "login_failed",
                email=payload.email,
                actor_id=stored_user.id if stored_user else None,
                details={"reason": "invalid_credentials"},
            )
            raise ValueError("Invalid credentials")

        # Successful login - reset failed attempts
        user_repo.reset_failed_attempts(payload.email)

        access_token = f"atk_{uuid4().hex}"
        refresh_token = f"rtk_{uuid4().hex}"
        expires_at = cls._now() + timedelta(seconds=TOKEN_TTL_SECONDS)
        family_id = f"fam_{uuid4().hex}"

        token_family_repo = TokenFamilyRepository(db)
        token_family_repo.create_family(family_id=family_id, email=payload.email)

        session_repo.create_session(
            access_token=hash_token(access_token),
            refresh_token=hash_token(refresh_token),
            email=payload.email,
            family_id=family_id,
            sequence=0,
            expires_at=expires_at,
        )

        audit_log.log_event(db, "login_success", email=payload.email, actor_id=stored_user.id)

        return AuthSessionResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=TOKEN_TTL_SECONDS,
            user=user_orm_to_pydantic(stored_user),
        )

    @classmethod
    def get_user_for_token(cls, token: str, db: Session = None) -> AuthUser | None:
        if db is None:
            with SessionLocal() as db:
                return cls._get_user_for_token_with_db(token, db)
        return cls._get_user_for_token_with_db(token, db)

    @classmethod
    def _get_user_for_token_with_db(cls, token: str, db: Session) -> AuthUser | None:
        session_repo = SessionRepository(db)
        user_repo = UserRepository(db)

        hashed_token = hash_token(token)
        session = session_repo.get_session(hashed_token)
        if not session:
            return None

        if cls._is_expired(session.expires_at):
            session_repo.delete_session(hashed_token)
            return None

        stored_user = user_repo.get_by_email(session.email)
        return user_orm_to_pydantic(stored_user) if stored_user else None

    @classmethod
    def refresh(cls, refresh_token: str, db: Session = None) -> AuthSessionResponse:
        if db is None:
            with SessionLocal() as db:
                return cls._refresh_with_db(refresh_token, db)
        return cls._refresh_with_db(refresh_token, db)

    @classmethod
    def _refresh_with_db(cls, refresh_token: str, db: Session) -> AuthSessionResponse:
        session_repo = SessionRepository(db)
        user_repo = UserRepository(db)
        token_family_repo = TokenFamilyRepository(db)

        hashed_refresh = hash_token(refresh_token)
        old_session = session_repo.get_session_by_refresh_token(hashed_refresh)
        if not old_session:
            raise ValueError("Invalid or expired refresh token")

        email = old_session.email
        family_id = old_session.family_id

        # Check if account is locked
        if user_repo.is_account_locked(email):
            audit_log.log_event(db, "refresh_failed_locked", email=email, details={"reason": "account_locked"})
            raise ValueError("Account is temporarily locked")

        # Handle pre-family sessions (backward compatibility)
        if family_id is None:
            family_id = f"fam_{uuid4().hex}"
            token_family_repo.create_family(family_id=family_id, email=email)
            # Migrate old session to new family so sequence checks work
            old_session.family_id = family_id
            old_session.sequence = 0
            db.commit()

        family = token_family_repo.get_family(family_id)
        if not family:
            raise ValueError("Invalid token family")

        stored_user = user_repo.get_by_email(email)

        if family.compromised:
            audit_log.log_event(
                db,
                "refresh_failed_compromised",
                email=email,
                actor_id=stored_user.user_id if stored_user else None,
                details={"family_id": family_id, "reason": "compromised_family"},
            )
            raise ValueError("Session family has been compromised")

        # Reuse detection: if this token's sequence is behind the family's current sequence,
        # it means this token was already rotated and is being replayed.
        if old_session.sequence < family.current_sequence:
            token_family_repo.compromise_family(family_id)
            session_repo.delete_sessions_by_family(family_id)
            audit_log.log_event(
                db,
                "refresh_token_reuse",
                email=email,
                actor_id=stored_user.user_id if stored_user else None,
                details={
                    "family_id": family_id,
                    "sequence": old_session.sequence,
                    "expected": family.current_sequence,
                    "reason": "token_replay_detected",
                },
            )
            raise ValueError("Refresh token reuse detected. Session family invalidated.")

        # Legitimate rotation
        token_family_repo.increment_sequence(family_id)
        session_repo.delete_session(old_session.access_token)

        if not stored_user:
            raise ValueError("User not found")

        new_access = f"atk_{uuid4().hex}"
        new_refresh = f"rtk_{uuid4().hex}"
        expires_at = cls._now() + timedelta(seconds=TOKEN_TTL_SECONDS)

        session_repo.create_session(
            access_token=hash_token(new_access),
            refresh_token=hash_token(new_refresh),
            email=email,
            family_id=family_id,
            sequence=family.current_sequence + 1,
            expires_at=expires_at,
        )

        audit_log.log_event(
            db,
            "refresh",
            email=email,
            actor_id=stored_user.user_id,
            details={"family_id": family_id, "event": "token_rotation"},
        )

        return AuthSessionResponse(
            access_token=new_access,
            refresh_token=new_refresh,
            expires_in=TOKEN_TTL_SECONDS,
            user=user_orm_to_pydantic(stored_user),
        )

    @classmethod
    def logout(cls, token: str, db: Session = None) -> None:
        if db is None:
            with SessionLocal() as db:
                return cls._logout_with_db(token, db)
        return cls._logout_with_db(token, db)

    @classmethod
    def _logout_with_db(cls, token: str, db: Session) -> None:
        session_repo = SessionRepository(db)
        hashed_token = hash_token(token)
        session = session_repo.get_session(hashed_token)
        if session:
            email = session.email
            session_repo.delete_session(hashed_token)
            audit_log.log_event(db, "logout", email=email)

    @classmethod
    def get_user_sessions(cls, email: str, db: Session = None) -> list:
        """Get all active sessions for a user (without token material)."""
        if db is None:
            with SessionLocal() as db:
                return cls._get_user_sessions_with_db(email, db)
        return cls._get_user_sessions_with_db(email, db)

    @classmethod
    def _get_user_sessions_with_db(cls, email: str, db: Session) -> list:
        session_repo = SessionRepository(db)
        sessions = session_repo.list_sessions_by_email(email)

        # Return session info without sensitive token material
        session_list = []
        for session in sessions:
            is_expired = cls._is_expired(session.expires_at)
            session_list.append(
                {
                    "access_token_preview": session.access_token[:12] + "..." if session.access_token else None,
                    "refresh_token_preview": session.refresh_token[:12] + "..." if session.refresh_token else None,
                    "email": session.email,
                    "expires_at": session.expires_at,
                    "created_at": session.created_at,
                    "is_active": not is_expired,
                }
            )

        return session_list

    @classmethod
    def logout_all_sessions(cls, email: str, db: Session = None) -> int:
        """Logout all sessions for a user. Returns count of invalidated sessions."""
        if db is None:
            with SessionLocal() as db:
                return cls._logout_all_sessions_with_db(email, db)
        return cls._logout_all_sessions_with_db(email, db)

    @classmethod
    def _logout_all_sessions_with_db(cls, email: str, db: Session) -> int:
        session_repo = SessionRepository(db)
        token_family_repo = TokenFamilyRepository(db)
        count = session_repo.delete_sessions_by_email(email)
        token_family_repo.delete_families_by_email(email)
        audit_log.log_event(db, "logout_all_sessions", email=email, details={"sessions_invalidated": count})
        return count
