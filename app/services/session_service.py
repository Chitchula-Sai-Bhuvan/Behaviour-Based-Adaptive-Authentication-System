"""
services/session_service.py
────────────────────────────
Login session lifecycle (create, validate, terminate).

Sessions act as a container for all events produced during one
user's browsing lifetime.  Binding the JWT to a session_id means
a revoked session invalidates all its tokens even before they expire.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.core.config import settings
from app.models.login_session import LoginSession
from app.core.logger import get_logger

logger = get_logger(__name__)


def create_session(
    db: DBSession,
    user_id: int,
    device_fingerprint: str,
    ip_address: str,
    user_agent: Optional[str] = None,
) -> LoginSession:
    """Create and persist a new login session."""
    now = datetime.utcnow()
    session = LoginSession(
        session_id=str(uuid.uuid4()),
        user_id=user_id,
        device_fingerprint=device_fingerprint,
        ip_address=ip_address,
        user_agent=user_agent,
        created_at=now,
        last_active_at=now,
        expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        is_active=True,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    logger.info("Session created", extra={"session_id": session.session_id, "user_id": user_id})
    return session


def get_session(db: DBSession, session_id: str) -> Optional[LoginSession]:
    return db.query(LoginSession).filter(LoginSession.session_id == session_id).first()


def is_session_active(db: DBSession, session_id: str) -> bool:
    """Return True only if the session exists, is active, and has not expired."""
    session = get_session(db, session_id)
    if not session or not session.is_active:
        return False
    return datetime.utcnow() < session.expires_at


def touch_session(db: DBSession, session_id: str) -> None:
    """Update last_active_at to the current time (extend idle timeout)."""
    db.query(LoginSession).filter(LoginSession.session_id == session_id).update(
        {"last_active_at": datetime.utcnow()}
    )
    db.commit()


def terminate_session(db: DBSession, session_id: str, reason: str = "LOGOUT") -> bool:
    """Invalidate a session. Returns True if found."""
    session = get_session(db, session_id)
    if not session:
        return False
    session.is_active = False
    session.terminated_reason = reason
    db.commit()
    logger.info("Session terminated", extra={"session_id": session_id, "reason": reason})
    return True


def terminate_all_user_sessions(db: DBSession, user_id: int, reason: str = "SECURITY") -> int:
    """Terminate every active session for a user. Returns count invalidated."""
    count = (
        db.query(LoginSession)
        .filter(LoginSession.user_id == user_id, LoginSession.is_active == True)
        .update({"is_active": False, "terminated_reason": reason})
    )
    db.commit()
    logger.info("All sessions terminated", extra={"user_id": user_id, "count": count, "reason": reason})
    return count
