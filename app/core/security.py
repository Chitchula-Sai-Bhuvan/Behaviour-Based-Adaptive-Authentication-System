"""
core/security.py
────────────────
Password hashing, device fingerprinting, and JWT utilities.

Key design decisions:
  • bcrypt called directly (passlib is incompatible with bcrypt >= 5.0)
  • Each JWT carries a unique `jti` (JWT ID) for revocation support
  • Access tokens are bound to a device fingerprint to resist token theft
  • Refresh tokens are long-lived and stored by jti in the DB
"""

import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings


# ── Password Hashing ───────────────────────────────────────────────────────────

def hash_password(plain_password: str) -> str:
    """Return a bcrypt hash of the plain-text password."""
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time bcrypt comparison."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


# ── Password Policy ────────────────────────────────────────────────────────────

def validate_password_policy(password: str) -> list[str]:
    """
    Return a list of policy violations.  Empty list means the password passes.

    Rules (all configurable in settings):
      • Minimum length
      • At least one uppercase letter
      • At least one digit
      • At least one special character
    """
    errors: list[str] = []
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters.")
    if settings.PASSWORD_REQUIRE_UPPER and not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if settings.PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
        errors.append("Password must contain at least one digit.")
    if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("Password must contain at least one special character.")
    return errors


# ── Device Fingerprinting ──────────────────────────────────────────────────────

def compute_device_fingerprint(ip_address: str, user_agent: str, accept_language: str = "") -> str:
    """
    Produce a stable, one-way identifier for a client device.

    The fingerprint is an SHA-256 hash of the IP, User-Agent, and
    Accept-Language header.  It is NOT a secret — it is used only to
    detect whether a new device is attempting to authenticate.

    In production you can extend this with TLS JA3 fingerprints or
    canvas fingerprinting from the frontend.
    """
    raw = f"{ip_address}|{user_agent}|{accept_language}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ── JWT Tokens ─────────────────────────────────────────────────────────────────

def _build_token(
    subject: str,
    user_id: int,
    token_type: str,
    device_fingerprint: str,
    expires_delta: timedelta,
    extra_claims: Optional[dict] = None,
) -> tuple[str, str]:
    """
    Internal: build and sign a JWT.  Returns (encoded_token, jti).

    The `jti` (JWT ID) is a UUID4 stored in every token.
    It allows the revoked_tokens table to blacklist individual tokens
    without invalidating the entire user session.
    """
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    payload: dict = {
        "sub": subject,
        "user_id": user_id,
        "type": token_type,
        "device": device_fingerprint,   # bind token to originating device
        "jti": jti,
        "iat": now,
        "exp": now + expires_delta,
    }
    if extra_claims:
        payload.update(extra_claims)
    encoded = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded, jti


def create_access_token(
    username: str,
    user_id: int,
    device_fingerprint: str,
    session_id: Optional[str] = None,
) -> tuple[str, str]:
    """
    Create a short-lived access token.
    Returns (token_string, jti).
    """
    extra = {"session_id": session_id} if session_id else {}
    return _build_token(
        subject=username,
        user_id=user_id,
        token_type="access",
        device_fingerprint=device_fingerprint,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        extra_claims=extra,
    )


def create_refresh_token(
    username: str,
    user_id: int,
    device_fingerprint: str,
) -> tuple[str, str]:
    """Create a long-lived refresh token.  Returns (token_string, jti)."""
    return _build_token(
        subject=username,
        user_id=user_id,
        token_type="refresh",
        device_fingerprint=device_fingerprint,
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and verify any JWT.
    Returns the payload dict, or None if invalid / expired.
    Callers must still check the `type` claim and whether the jti is revoked.
    """
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None
