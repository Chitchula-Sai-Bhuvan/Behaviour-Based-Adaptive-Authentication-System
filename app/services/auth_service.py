"""
services/auth_service.py
─────────────────────────
User registration, credential verification, and account lockout.

Production additions over v1:
  • Password policy enforcement before storing
  • Account lockout after MAX_FAILED_LOGINS consecutive failures
  • last_login_at / last_login_ip updated on successful login
  • Failed login counter reset on success
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password, verify_password, validate_password_policy
from app.models.user import User
from app.core.logger import get_logger

logger = get_logger(__name__)


# ── User Management ────────────────────────────────────────────────────────────

class DuplicateUsernameError(ValueError):
    """Raised when the requested username is already taken."""


class PasswordPolicyError(ValueError):
    """Raised when the supplied password fails the strength policy."""


def create_user(db: Session, username: str, plain_password: str) -> User:
    """
    Register a new user after enforcing username uniqueness and password policy.

    Raises
    ------
    DuplicateUsernameError : username already exists.
    PasswordPolicyError    : password does not satisfy the strength policy.
    """
    # Duplicate check
    if db.query(User).filter(User.username == username).first():
        raise DuplicateUsernameError(f"Username {username!r} is already registered.")

    # Password policy
    violations = validate_password_policy(plain_password)
    if violations:
        raise PasswordPolicyError("Password policy: " + " | ".join(violations))

    user = User(
        username=username,
        password_hash=hash_password(plain_password),
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("User registered", extra={"username": username})
    return user


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


# ── Authentication with Lockout ────────────────────────────────────────────────

def authenticate_user(
    db: Session,
    username: str,
    plain_password: str,
    ip_address: str,
) -> tuple[Optional[User], str]:
    """
    Verify credentials.

    Returns (User, "ok") on success.
    Returns (None, reason) on failure where reason is one of:
      "not_found", "locked", "bad_password"

    Side effects:
      • Increments failed_login_attempts on failure.
      • Locks the account when MAX_FAILED_LOGINS is exceeded.
      • Resets counter and updates last_login context on success.
    """
    user = get_user_by_username(db, username)
    if not user:
        logger.warning("Login attempt for unknown user", extra={"username": username, "ip": ip_address})
        return None, "not_found"

    # ── Lockout check ──────────────────────────────────────────────
    if user.is_locked():
        logger.warning("Login attempt on locked account", extra={"user_id": user.id, "ip": ip_address})
        return None, "locked"

    # ── Password verification ──────────────────────────────────────
    if not verify_password(plain_password, user.password_hash):
        _record_failed_attempt(db, user)
        logger.warning("Failed login attempt", extra={"user_id": user.id, "ip": ip_address,
                                                       "attempts": user.failed_login_attempts})
        return None, "bad_password"

    # ── Success: reset counter, record context ─────────────────────
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()
    user.last_login_ip = ip_address
    db.commit()
    db.refresh(user)
    logger.info("Login success", extra={"user_id": user.id, "ip": ip_address})
    return user, "ok"


def _record_failed_attempt(db: Session, user: User) -> None:
    """Increment failure counter and lock if threshold exceeded."""
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.MAX_FAILED_LOGINS:
        user.locked_until = datetime.utcnow() + timedelta(
            minutes=settings.LOCKOUT_DURATION_MINUTES
        )
        logger.warning(
            "Account locked",
            extra={"user_id": user.id, "locked_until": str(user.locked_until)},
        )
    db.commit()


# ── Token Revocation ───────────────────────────────────────────────────────────

def revoke_token(
    db: Session,
    jti: str,
    user_id: int,
    expires_at: datetime,
    reason: str = "LOGOUT",
) -> None:
    """Insert a row into revoked_tokens and cache in Redis."""
    from app.models.revoked_token import RevokedToken
    record = RevokedToken(jti=jti, user_id=user_id, expires_at=expires_at, reason=reason)
    db.add(record)
    db.commit()

    # Also cache in Redis for fast lookup
    from app.core.redis_client import get_redis, RedisCounters
    r = get_redis()
    if r:
        ttl = max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
        RedisCounters(r).revoke_jti(jti, ttl)
    logger.info("Token revoked", extra={"user_id": user_id, "jti": jti, "reason": reason})


def is_token_revoked(db: Session, jti: str) -> bool:
    """Check Redis first (fast), then DB (authoritative)."""
    from app.core.redis_client import get_redis, RedisCounters
    r = get_redis()
    if r and RedisCounters(r).is_jti_revoked(jti):
        return True
    # DB fallback
    from app.models.revoked_token import RevokedToken
    return db.query(RevokedToken).filter(RevokedToken.jti == jti).first() is not None
