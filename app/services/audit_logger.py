"""
services/audit_logger.py
─────────────────────────
Tamper-evident audit log writer.

Every auth event is stored with a `chain_hash` that is the SHA-256 of:

    SHA-256( prev_chain_hash || event_id || user_id || event_type || timestamp )

Verifying the chain: iterate rows in ascending event_id order and
recompute each hash.  Any modification to a row breaks the chain at
that row, revealing tampering.  This provides lightweight, database-
native tamper evidence without requiring a blockchain or external HSM.

The `GENESIS_HASH` is a well-known constant that seeds the chain.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent, EventType
from app.core.logger import get_logger

logger = get_logger(__name__)

# Seed value for the first event in the chain
GENESIS_HASH = "0" * 64


def _compute_link(
    prev_hash: str,
    event_id: int,
    user_id: int,
    event_type: str,
    timestamp: datetime,
) -> str:
    """Compute the chain hash for a single event."""
    raw = f"{prev_hash}|{event_id}|{user_id}|{event_type}|{timestamp.isoformat()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _get_last_chain_hash(db: Session, user_id: int) -> str:
    """Return the most recent chain_hash for this user, or GENESIS_HASH."""
    row = (
        db.execute(
            select(AuthEvent.chain_hash)
            .where(AuthEvent.user_id == user_id)
            .order_by(AuthEvent.event_id.desc())
            .limit(1)
        )
        .scalar_one_or_none()
    )
    return row if row else GENESIS_HASH


def log_event(
    db: Session,
    user_id: int,
    event_type: EventType,
    ip_address: str,
    device_info: Optional[str] = None,
    device_fingerprint: Optional[str] = None,
    session_id: Optional[str] = None,
    success: bool = True,
) -> AuthEvent:
    """
    Write one auth event to the database with a computed chain_hash.

    The hash is computed AFTER the row is flushed (so we have event_id),
    then the row is updated and committed.
    """
    # Truncate to whole seconds: MySQL DATETIME stores only second-precision.
    # Both the stored timestamp and the verification re-read will then produce
    # the same isoformat() string, keeping the chain hashes consistent.
    now = datetime.utcnow().replace(microsecond=0)

    # Fetch the previous hash BEFORE flushing the new row.
    # If called after flush, the newly-flushed row (chain_hash=NULL) would be
    # the most recent and would incorrectly resolve to GENESIS_HASH.
    prev_hash = _get_last_chain_hash(db, user_id)

    event = AuthEvent(
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        device_info=device_info or "unknown",
        device_fingerprint=device_fingerprint,
        session_id=session_id,
        success=success,
        timestamp=now,
    )
    db.add(event)
    db.flush()   # assigns event_id without committing

    # Now we have event_id — compute and attach the chain hash
    event.chain_hash = _compute_link(
        prev_hash=prev_hash,
        event_id=event.event_id,
        user_id=user_id,
        event_type=event_type.value,
        timestamp=now,
    )
    db.commit()
    db.refresh(event)

    logger.info(
        "Auth event logged",
        extra={
            "event_id": event.event_id,
            "user_id": user_id,
            "event_type": event_type.value,
            "ip": ip_address,
            "success": success,
        },
    )
    return event


def verify_chain(db: Session, user_id: int) -> dict:
    """
    Verify the integrity of the audit chain for one user.

    Returns:
        { "valid": True, "events_checked": N }
        or
        { "valid": False, "broken_at_event_id": X, "events_checked": N }
    """
    events = (
        db.execute(
            select(AuthEvent)
            .where(AuthEvent.user_id == user_id)
            .order_by(AuthEvent.event_id.asc())
        )
        .scalars()
        .all()
    )

    prev_hash = GENESIS_HASH
    for ev in events:
        expected = _compute_link(prev_hash, ev.event_id, ev.user_id, ev.event_type.value, ev.timestamp)
        if ev.chain_hash != expected:
            logger.warning(
                "Audit chain broken",
                extra={"user_id": user_id, "event_id": ev.event_id},
            )
            return {"valid": False, "broken_at_event_id": ev.event_id, "events_checked": len(events)}
        prev_hash = ev.chain_hash

    return {"valid": True, "events_checked": len(events)}
