"""
models/mfa_challenge.py
────────────────────────
mfa_challenges table — one row per issued MFA push notification.

Security properties enforced by this design:
  • Each challenge has a UUID `challenge_id` — prevents replay attacks
    because re-using an old challenge_id will find a `used=True` row.
  • `expires_at` enforces a hard TTL (default 5 minutes).
  • `used` is set to True atomically when the user responds.
  • `device_fingerprint` ties the challenge to the originating device.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class MFAChallenge(Base):
    __tablename__ = "mfa_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # The unique, unguessable ID the client must echo back to approve/deny
    challenge_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, index=True,
        default=lambda: str(uuid.uuid4()),
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # SHA-256 device fingerprint of the requestor
    device_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    # IP that requested the challenge
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)

    issued_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                  default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # True once the user approves or denies — prevents replay
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped["User"] = relationship("User")  # noqa: F821

    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        exp = self.expires_at
        # MySQL returns offset-naive datetimes; normalise for comparison
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now >= exp

    def is_valid(self) -> bool:
        """A challenge is valid only if it is unused and not expired."""
        return not self.used and not self.is_expired()

    def __repr__(self) -> str:
        return f"<MFAChallenge id={self.challenge_id!r} user={self.user_id} used={self.used}>"
