"""
api/logs.py
────────────
GET /api/logs/events       — auth events (filterable by user_id)
GET /api/logs/decisions    — risk decisions (filterable by user_id)
GET /api/logs/sessions     — login sessions
GET /api/logs/devices      — trusted devices
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.auth_event import AuthEvent
from app.models.risk_decision import RiskDecision
from app.models.login_session import LoginSession
from app.models.trusted_device import TrustedDevice
from app.api.schemas import AuthEventOut, RiskDecisionOut, LoginSessionOut, TrustedDeviceOut

router = APIRouter(tags=["Logs"])


@router.get("/logs/events", response_model=List[AuthEventOut],
            summary="Authentication event log")
def get_auth_events(
    user_id: Optional[int] = Query(None),
    limit:   int            = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Return auth events newest-first. Omit user_id for all-users admin view."""
    q = db.query(AuthEvent).order_by(AuthEvent.timestamp.desc())
    if user_id is not None:
        q = q.filter(AuthEvent.user_id == user_id)
    return q.limit(limit).all()


@router.get("/logs/decisions", response_model=List[RiskDecisionOut],
            summary="Risk decision history")
def get_risk_decisions(
    user_id: Optional[int] = Query(None),
    limit:   int            = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Return risk decisions newest-first."""
    q = db.query(RiskDecision).order_by(RiskDecision.timestamp.desc())
    if user_id is not None:
        q = q.filter(RiskDecision.user_id == user_id)
    return q.limit(limit).all()


@router.get("/logs/sessions", response_model=List[LoginSessionOut],
            summary="Login sessions")
def get_sessions(
    user_id: Optional[int] = Query(None),
    active_only: bool       = Query(False),
    limit:   int            = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Return login sessions newest-first. Set active_only=true to filter inactive."""
    q = db.query(LoginSession).order_by(LoginSession.created_at.desc())
    if user_id is not None:
        q = q.filter(LoginSession.user_id == user_id)
    if active_only:
        q = q.filter(LoginSession.is_active == True)
    return q.limit(limit).all()


@router.get("/logs/devices", response_model=List[TrustedDeviceOut],
            summary="Trusted device list")
def get_trusted_devices(
    user_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    """Return trusted devices for a user, or all users if user_id is omitted."""
    q = db.query(TrustedDevice).order_by(TrustedDevice.last_seen_at.desc())
    if user_id is not None:
        q = q.filter(TrustedDevice.user_id == user_id)
    return q.all()
