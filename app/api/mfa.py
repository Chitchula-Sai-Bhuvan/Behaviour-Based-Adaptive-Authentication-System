"""
api/mfa.py
──────────
POST /api/mfa/request  — issue a challenge (UUID returned, valid 5 min)
POST /api/mfa/respond  — approve or deny, providing the challenge_id

Anti-replay security:
  • Each challenge has a unique UUID — cannot be guessed or replicated
  • Responding once (approve OR deny) permanently invalidates the challenge
  • Expired challenges are rejected
  • Rate-limited to 20 requests/min per IP
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.config import settings
from app.core.limiter import limiter
from app.core.security import compute_device_fingerprint
from app.models.user import User
from app.models.auth_event import EventType
from app.services.audit_logger import log_event
from app.services.mfa_service import issue_challenge, respond_to_challenge
from app.services.decision_controller import run_evaluation
from app.services.behaviour_monitor import record_mfa_request, record_approval
from app.api.schemas import MFARequestResponse, MFARespondRequest, MFARespondResponse

router = APIRouter(tags=["MFA"])


@router.post(
    "/request",
    response_model=MFARequestResponse,
    summary="Issue an MFA push challenge (returns a unique challenge_id)",
)
@limiter.limit(settings.RATE_LIMIT_MFA)
def mfa_request(
    request: Request,
    user_id: int,
    session_id: str = "",
    db: Session = Depends(get_db),
):
    """
    Issue an MFA push notification challenge.

    The client must present the returned `challenge_id` when calling
    /mfa/respond.  This prevents replay of previously seen approvals.

    Rate-limited to {RATE_LIMIT_MFA} per IP.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    if user.is_locked():
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account is locked.")

    ip   = request.client.host if request.client else "unknown"
    ua   = request.headers.get("user-agent", "unknown")
    lang = request.headers.get("accept-language", "")
    fingerprint = compute_device_fingerprint(ip, ua, lang)

    try:
        challenge = issue_challenge(db, user_id, fingerprint, ip)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc))

    # Audit + Redis counter
    log_event(
        db, user_id, EventType.MFA_REQUEST, ip,
        device_info=ua, device_fingerprint=fingerprint,
        session_id=session_id or None,
    )
    record_mfa_request(user_id)

    return MFARequestResponse(
        message="MFA push notification issued. Awaiting response.",
        user_id=user_id,
        challenge_id=challenge.challenge_id,
    )


@router.post(
    "/respond",
    response_model=MFARespondResponse,
    summary="Approve or deny an MFA challenge (challenge_id required)",
)
def mfa_respond(
    payload: MFARespondRequest,
    db: Session = Depends(get_db),
):
    """
    Process the user's MFA response.

    The `challenge_id` must match a valid, unused, non-expired challenge
    issued for this `user_id`.  The challenge is invalidated immediately
    upon use (approve OR deny) — no replays possible.

    A risk evaluation runs on every response.
    """
    user = db.query(User).filter(User.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    # Validate + consume the challenge
    ok, reason = respond_to_challenge(
        db=db,
        challenge_id=payload.challenge_id,
        user_id=payload.user_id,
        approved=payload.approved,
    )
    if not ok:
        error_map = {
            "not_found": "Challenge not found.",
            "already_used": "Challenge has already been used (replay blocked).",
            "expired": "Challenge has expired. Please request a new one.",
        }
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_map.get(reason, "Invalid challenge."),
        )

    ip = payload.ip_address or "unknown"
    ua = payload.device_info or "unknown"
    fingerprint = compute_device_fingerprint(ip, ua)

    event_type = EventType.APPROVE if payload.approved else EventType.DENY
    log_event(db, payload.user_id, event_type, ip, device_info=ua, device_fingerprint=fingerprint)

    if payload.approved:
        record_approval(payload.user_id)

    # Full risk evaluation after every response
    result = run_evaluation(
        db, payload.user_id,
        device_fingerprint=fingerprint,
        ip_address=ip,
    )

    action = "approved" if payload.approved else "denied"
    return MFARespondResponse(
        message=f"MFA {action}. Risk evaluation complete.",
        event_type=event_type.value,
        risk_decision=result["decision"],
        risk_score=result["risk_score"],
        triggered_signals=result["triggered_signals"],
    )
