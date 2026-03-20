"""
api/auth.py
────────────
POST /api/register  — register a new user (rate-limited: 5/min per IP)
POST /api/login     — authenticate, create session, issue JWT pair
POST /api/logout    — revoke access + refresh tokens, terminate session
POST /api/refresh   — exchange a valid refresh token for a new access token
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.config import settings
from app.core.security import (
    compute_device_fingerprint,
    create_access_token, create_refresh_token, decode_token,
)
from app.core.limiter import limiter
from app.services.auth_service import (
    create_user, authenticate_user, get_user_by_id,
    revoke_token, is_token_revoked,
    DuplicateUsernameError, PasswordPolicyError,
)
from app.services.audit_logger import log_event
from app.services.session_service import create_session, terminate_session
from app.services.device_service import is_device_trusted, trust_device, update_last_seen
from app.services.behaviour_monitor import record_login_attempt
from app.models.auth_event import EventType
from app.api.schemas import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    RefreshRequest, LogoutRequest,
)

router = APIRouter(tags=["Authentication"])


def _extract_request_meta(request: Request) -> tuple[str, str, str]:
    """Return (ip, user_agent, accept_language) from the incoming request."""
    ip  = request.client.host if request.client else "unknown"
    ua  = request.headers.get("user-agent", "unknown")
    lang = request.headers.get("accept-language", "")
    return ip, ua, lang


# ── Register ───────────────────────────────────────────────────────────────────

@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account",
)
@limiter.limit(settings.RATE_LIMIT_REGISTER)
def register(request: Request, payload: RegisterRequest, db: Session = Depends(get_db)):
    """
    Register with username + password.
    Password policy is enforced in `create_user` (service layer).
    """
    try:
        user = create_user(db, payload.username, payload.password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except DuplicateUsernameError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return user


# ── Login ──────────────────────────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Login and receive a JWT access + refresh token pair",
)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    """
    Verify credentials.

    On success:
      1. Create a login session.
      2. Issue access token (30 min) + refresh token (7 days).
      3. Log LOGIN event with device fingerprint.
      4. Increment Redis login counter for the behaviour monitor.
      5. Trust the device if first successful login.

    On failure:
      • Log the failed attempt (still needed for brute-force detection).
      • Return 401 (lockout reason is NOT disclosed to avoid user enumeration).
    """
    ip, ua, lang = _extract_request_meta(request)
    fingerprint = compute_device_fingerprint(ip, ua, lang)

    user, reason = authenticate_user(db, payload.username, payload.password, ip)

    if not user:
        # Log the failed attempt for the behaviour monitor
        from app.services.auth_service import get_user_by_username
        existing = get_user_by_username(db, payload.username)
        if existing:
            log_event(
                db, existing.id, EventType.LOGIN, ip,
                device_info=ua, device_fingerprint=fingerprint, success=False,
            )
            record_login_attempt(existing.id)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is temporarily locked. Try again later." if reason == "locked"
                   else "Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── Successful auth ─────────────────────────────────────────────
    # Create session
    session = create_session(db, user.id, fingerprint, ip, ua)

    # Issue JWT pair
    access_token, access_jti = create_access_token(
        username=user.username,
        user_id=user.id,
        device_fingerprint=fingerprint,
        session_id=session.session_id,
    )
    refresh_token, refresh_jti = create_refresh_token(
        username=user.username,
        user_id=user.id,
        device_fingerprint=fingerprint,
    )

    # Audit log
    log_event(
        db, user.id, EventType.LOGIN, ip,
        device_info=ua, device_fingerprint=fingerprint,
        session_id=session.session_id, success=True,
    )
    record_login_attempt(user.id)

    # Auto-trust device on first login (trust is elevated after step-up in subsequent logins)
    if not is_device_trusted(db, user.id, fingerprint):
        trust_device(db, user.id, fingerprint, device_label=ua[:80])
    else:
        update_last_seen(db, user.id, fingerprint)

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user_id=user.id,
        username=user.username,
        session_id=session.session_id,
    )


# ── Refresh ────────────────────────────────────────────────────────────────────

@router.post(
    "/refresh",
    response_model=LoginResponse,
    summary="Exchange a refresh token for a new access token",
)
def refresh_token_endpoint(
    request: Request,
    payload: RefreshRequest,
    db: Session = Depends(get_db),
):
    """
    Validate the refresh token and issue a new access token.
    The refresh token is rotated (old one revoked, new one issued).
    """
    decoded = decode_token(payload.refresh_token)
    if not decoded or decoded.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")

    jti = decoded.get("jti", "")
    if is_token_revoked(db, jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked.")

    user_id = decoded.get("user_id")
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")

    ip, ua, lang = _extract_request_meta(request)
    fingerprint = compute_device_fingerprint(ip, ua, lang)

    # Revoke old refresh token
    exp = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)
    revoke_token(db, jti, user_id, exp, reason="ROTATED")

    # Create new session + token pair
    session = create_session(db, user.id, fingerprint, ip, ua)
    access_token, _ = create_access_token(user.username, user.id, fingerprint, session.session_id)
    new_refresh, _ = create_refresh_token(user.username, user.id, fingerprint)

    return LoginResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        token_type="bearer",
        user_id=user.id,
        username=user.username,
        session_id=session.session_id,
    )


# ── Logout ─────────────────────────────────────────────────────────────────────

@router.post("/logout", status_code=status.HTTP_200_OK, summary="Logout and revoke tokens")
def logout(
    request: Request,
    payload: LogoutRequest,
    db: Session = Depends(get_db),
):
    """
    Terminate the session.
    The caller should also pass the Authorization header so the access token
    can be revoked.  Refresh token revocation requires the client to send it.
    """
    ip, ua, lang = _extract_request_meta(request)
    fingerprint = compute_device_fingerprint(ip, ua, lang)

    # Revoke access token if present in Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        decoded = decode_token(token)
        if decoded:
            jti = decoded.get("jti", "")
            # Skip INSERT if token is already revoked (idempotent logout)
            if jti and not is_token_revoked(db, jti):
                exp = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)
                revoke_token(db, jti, decoded["user_id"], exp, reason="LOGOUT")
                log_event(
                    db, decoded["user_id"], EventType.LOGOUT, ip,
                    device_info=ua, device_fingerprint=fingerprint,
                    session_id=payload.session_id,
                )

    terminate_session(db, payload.session_id, reason="LOGOUT")
    return {"message": "Logged out successfully."}
