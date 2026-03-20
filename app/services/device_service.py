"""
services/device_service.py
───────────────────────────
Trusted device registry management.

When a user logs in from an unrecognised device, the `new_device_detected`
signal is raised (+20 risk points).  After the user completes step-up
verification on the new device, it can be promoted to trusted.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.trusted_device import TrustedDevice
from app.core.logger import get_logger

logger = get_logger(__name__)


def is_device_trusted(db: Session, user_id: int, device_fingerprint: str) -> bool:
    """Return True if this device fingerprint is in the user's trusted list."""
    result = (
        db.query(TrustedDevice)
        .filter(
            TrustedDevice.user_id == user_id,
            TrustedDevice.device_fingerprint == device_fingerprint,
            TrustedDevice.is_active == True,
        )
        .first()
    )
    return result is not None


def trust_device(
    db: Session,
    user_id: int,
    device_fingerprint: str,
    device_label: Optional[str] = None,
) -> TrustedDevice:
    """
    Add a device to the trusted list (or reactivate it if previously removed).

    Called after a successful step-up verification on a new device.
    """
    # Check for existing (possibly deactivated) record
    existing = (
        db.query(TrustedDevice)
        .filter(
            TrustedDevice.user_id == user_id,
            TrustedDevice.device_fingerprint == device_fingerprint,
        )
        .first()
    )

    if existing:
        existing.is_active = True
        existing.last_seen_at = datetime.now(timezone.utc)
        if device_label:
            existing.device_label = device_label
        db.commit()
        db.refresh(existing)
        logger.info("Device reactivated", extra={"user_id": user_id, "fp": device_fingerprint[:12]})
        return existing

    device = TrustedDevice(
        user_id=user_id,
        device_fingerprint=device_fingerprint,
        device_label=device_label,
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
        is_active=True,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    logger.info("Device trusted", extra={"user_id": user_id, "fp": device_fingerprint[:12]})
    return device


def update_last_seen(db: Session, user_id: int, device_fingerprint: str) -> None:
    """Touch last_seen_at for an existing trusted device."""
    db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user_id,
        TrustedDevice.device_fingerprint == device_fingerprint,
    ).update({"last_seen_at": datetime.now(timezone.utc)})
    db.commit()


def revoke_device(db: Session, user_id: int, device_fingerprint: str) -> bool:
    """Soft-revoke a trusted device. Returns True if the record was found."""
    device = db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user_id,
        TrustedDevice.device_fingerprint == device_fingerprint,
    ).first()
    if not device:
        return False
    device.is_active = False
    db.commit()
    logger.info("Device revoked", extra={"user_id": user_id, "fp": device_fingerprint[:12]})
    return True


def list_trusted_devices(db: Session, user_id: int) -> list[TrustedDevice]:
    return (
        db.query(TrustedDevice)
        .filter(TrustedDevice.user_id == user_id, TrustedDevice.is_active == True)
        .order_by(TrustedDevice.last_seen_at.desc())
        .all()
    )
