"""
models/revoked_token.py
────────────────────────
revoked_tokens table — JWT revocation blacklist.

When a user logs out, changes their password, or we detect suspicious
activity, we INSERT the token's `jti` here.  The authentication
middleware checks this table (or Redis cache) before honouring any
access token.

Schema note:
  The table only stores the `jti` UUID and the expiry date.  We do NOT
  store the full token — the jti alone is sufficient and avoids storing
  sensitive material in the DB.

Maintenance:
  Rows can be safely deleted once `expires_at` has passed; the token
  would be invalid anyway.  Schedule a nightly cleanup job to prune
  expired rows and keep the table small.
"""

from datetime import datetime, timezone

from sqlalchemy import Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # The `jti` claim from the JWT payload — a UUID4 unique to each token
    jti: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)

    # Which user this token belonged to (for audit purposes)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Original expiry from the JWT `exp` claim — used for cleanup jobs
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # When was this token revoked?
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Why was it revoked? (LOGOUT, PASSWORD_CHANGE, SUSPICIOUS_ACTIVITY, ADMIN)
    reason: Mapped[str] = mapped_column(String(64), nullable=False, default="LOGOUT")

    def __repr__(self) -> str:
        return f"<RevokedToken jti={self.jti!r} user={self.user_id} reason={self.reason}>"
