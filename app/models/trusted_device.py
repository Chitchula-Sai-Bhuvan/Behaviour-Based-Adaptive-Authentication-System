"""
models/trusted_device.py
─────────────────────────
trusted_devices table — per-user list of recognised device fingerprints.

When a user authenticates successfully from a device that is NOT in
this table, the behaviour monitor raises the `new_device_detected`
signal (+20 risk points).

A device is added to this table after a successful step-up verification
on a new device (i.e. the user confirms it is theirs).

The `device_fingerprint` column matches the SHA-256 hash produced by
`compute_device_fingerprint()` in core/security.py.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class TrustedDevice(Base):
    __tablename__ = "trusted_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # SHA-256(IP|User-Agent|Accept-Language) — same hash as auth_events.device_fingerprint
    device_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Human-friendly nickname (set by the UI, e.g. "Chrome on Windows")
    device_label: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Soft-revoke: admin can mark a device as untrusted without deleting the row
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="trusted_devices")  # noqa: F821

    def __repr__(self) -> str:
        return f"<TrustedDevice user={self.user_id} fp={self.device_fingerprint[:12]}... active={self.is_active}>"
