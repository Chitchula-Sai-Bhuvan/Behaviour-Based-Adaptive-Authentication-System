"""
models/auth_event.py
────────────────────
auth_events table — append-only tamper-evident audit log.

v2 additions over v1:
  • device_fingerprint  — SHA-256 of IP + User-Agent + Accept-Language
  • session_id          — FK to login_sessions (ties event to a session)
  • success             — whether the action succeeded (e.g. login passed/failed)
  • chain_hash          — SHA-256 of (prev_hash || event_data) for tamper evidence
"""

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Integer, String, DateTime, ForeignKey, Boolean, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class EventType(str, enum.Enum):
    LOGIN        = "LOGIN"
    MFA_REQUEST  = "MFA_REQUEST"
    APPROVE      = "APPROVE"
    DENY         = "DENY"
    LOGOUT       = "LOGOUT"
    TOKEN_REVOKE = "TOKEN_REVOKE"
    LOCKOUT      = "LOCKOUT"


class AuthEvent(Base):
    __tablename__ = "auth_events"

    event_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True, index=True)
    user_id:  Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    event_type: Mapped[EventType] = mapped_column(SAEnum(EventType), nullable=False)

    ip_address:          Mapped[str]           = mapped_column(String(45),  nullable=False)
    device_info:         Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    # SHA-256 of IP|User-Agent|Accept-Language
    device_fingerprint:  Mapped[Optional[str]] = mapped_column(String(64),  nullable=True, index=True)
    # FK to login_sessions — allows grouping all events in one session
    session_id:          Mapped[Optional[str]] = mapped_column(String(64),  nullable=True, index=True)
    # Did the action succeed? (False for failed logins, blocked MFA, etc.)
    success:             Mapped[bool]          = mapped_column(Boolean, default=True, nullable=False)

    # ── Tamper-evident hash chain ─────────────────────────────────
    # chain_hash = SHA-256(prev_chain_hash || event_id || user_id || event_type || timestamp)
    # Verifying the chain detects any row that has been silently altered.
    chain_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    user: Mapped["User"] = relationship("User", back_populates="auth_events")  # noqa: F821

    def __repr__(self) -> str:
        return (
            f"<AuthEvent id={self.event_id} user={self.user_id} "
            f"type={self.event_type} success={self.success}>"
        )
