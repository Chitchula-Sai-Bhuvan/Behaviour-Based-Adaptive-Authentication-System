"""
models/user.py
──────────────
users table — core identity store.

v2 additions:
  • failed_login_attempts / locked_until  — account lockout
  • last_login_at / last_login_ip         — anomaly detection context
"""

from datetime import datetime, timezone
from typing import Optional, List, TYPE_CHECKING

from sqlalchemy import Integer, String, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.auth_event import AuthEvent
    from app.models.risk_decision import RiskDecision
    from app.models.trusted_device import TrustedDevice
    from app.models.login_session import LoginSession


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Lockout ────────────────────────────────────────────────────
    # failed_login_attempts resets to 0 on successful login.
    # locked_until=NULL means not locked; datetime means locked until then.
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Context for anomaly detection ──────────────────────────────
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # ── Relationships ──────────────────────────────────────────────
    auth_events:     Mapped[List["AuthEvent"]]    = relationship("AuthEvent",     back_populates="user", cascade="all, delete-orphan")
    risk_decisions:  Mapped[List["RiskDecision"]] = relationship("RiskDecision",  back_populates="user", cascade="all, delete-orphan")
    trusted_devices: Mapped[List["TrustedDevice"]]= relationship("TrustedDevice", back_populates="user", cascade="all, delete-orphan")
    login_sessions:  Mapped[List["LoginSession"]] = relationship("LoginSession",  back_populates="user", cascade="all, delete-orphan")

    # ── Helpers ────────────────────────────────────────────────────
    def is_locked(self) -> bool:
        """Return True if the account is currently locked out."""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r}>"
