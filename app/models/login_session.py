"""
models/login_session.py
────────────────────────
login_sessions table — one row per authenticated browser session.

A session is created on successful login and invalidated on logout or
when a risk decision of BLOCK is issued.  All auth_events produced
during a session reference this row via `session_id`.

The `session_id` is also embedded in the JWT access token so that
the middleware can verify the session is still active.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class LoginSession(Base):
    __tablename__ = "login_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # UUID embedded in the access token to tie tokens to sessions
    session_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, index=True,
        default=lambda: str(uuid.uuid4()),
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    device_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_address:         Mapped[str] = mapped_column(String(45),  nullable=False)
    user_agent:         Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_active_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # False = session is invalidated (logout or BLOCK decision)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # How was this session ended?  NULL = still active
    terminated_reason: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="login_sessions")  # noqa: F821

    def __repr__(self) -> str:
        return f"<LoginSession id={self.session_id!r} user={self.user_id} active={self.is_active}>"
