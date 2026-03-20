"""
services/mfa_service.py
────────────────────────
MFA challenge lifecycle management.

Flow
────
 1. issue_challenge()     — generate UUID challenge, store in DB + Redis
 2. respond_to_challenge() — validate challenge_id, mark used, return result
 3. Challenges expire after MFA_CHALLENGE_TTL_SECONDS (default: 5 min)
 4. A challenge can only be used ONCE (used=True prevents replay)

Anti-replay controls:
  • challenge_id is a UUID4 — unguessable
  • challenge is invalidated immediately on first use
  • Redis cache for O(1) existence check before hitting the DB
  • Max active challenges per user prevents pre-generating many at once
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.redis_client import get_redis, RedisCounters
from app.models.mfa_challenge import MFAChallenge
from app.core.logger import get_logger

logger = get_logger(__name__)


def issue_challenge(
    db: Session,
    user_id: int,
    device_fingerprint: str,
    ip_address: str,
) -> MFAChallenge:
    """
    Create a new MFA challenge for a user.

    Raises
    ------
    ValueError : if the user already has >= MFA_MAX_ACTIVE_CHALLENGES pending.
    """
    # Prevent pre-generating many challenges (defence against automation)
    now_utc = datetime.utcnow()       # naive UTC — matches MySQL DATETIME storage
    active_count = (
        db.query(MFAChallenge)
        .filter(
            MFAChallenge.user_id == user_id,
            MFAChallenge.used == False,
            MFAChallenge.expires_at > now_utc,
        )
        .count()
    )
    if active_count >= settings.MFA_MAX_ACTIVE_CHALLENGES:
        raise ValueError(
            f"Too many active MFA challenges ({active_count}). "
            "Please respond to the existing request."
        )

    challenge = MFAChallenge(
        challenge_id=str(uuid.uuid4()),
        user_id=user_id,
        device_fingerprint=device_fingerprint,
        ip_address=ip_address,
        issued_at=now_utc,
        expires_at=now_utc + timedelta(seconds=settings.MFA_CHALLENGE_TTL_SECONDS),
        used=False,
    )
    db.add(challenge)
    db.commit()
    db.refresh(challenge)

    # Cache in Redis for fast lookup
    r = get_redis()
    if r:
        RedisCounters(r).cache_challenge(
            challenge.challenge_id, user_id, settings.MFA_CHALLENGE_TTL_SECONDS
        )

    logger.info(
        "MFA challenge issued",
        extra={"user_id": user_id, "challenge_id": challenge.challenge_id, "ip": ip_address},
    )
    return challenge


def respond_to_challenge(
    db: Session,
    challenge_id: str,
    user_id: int,
    approved: bool,
) -> tuple[bool, str]:
    """
    Process a user's response to an MFA challenge.

    Returns
    -------
    (True, "approved") / (True, "denied") on success.
    (False, reason) if the challenge is invalid.

    Invalidates the challenge regardless of the user's decision.
    """
    # Redis fast path
    r = get_redis()
    if r:
        counters = RedisCounters(r)
        if not counters.challenge_exists(challenge_id):
            logger.warning("MFA challenge not found in Redis", extra={"challenge_id": challenge_id})
            # Fall through to DB check — Redis might have evicted it

    # DB authoritative check
    challenge = (
        db.query(MFAChallenge)
        .filter(
            MFAChallenge.challenge_id == challenge_id,
            MFAChallenge.user_id == user_id,
        )
        .first()
    )

    if not challenge:
        return False, "not_found"
    if challenge.used:
        logger.warning("Replay attempt on used MFA challenge", extra={"challenge_id": challenge_id})
        return False, "already_used"
    if challenge.is_expired():
        return False, "expired"

    # Invalidate immediately (atomic replay protection)
    challenge.used = True
    db.commit()

    # Remove from Redis cache
    if r:
        RedisCounters(r).invalidate_challenge(challenge_id)

    result = "approved" if approved else "denied"
    logger.info(
        "MFA challenge responded",
        extra={"challenge_id": challenge_id, "user_id": user_id, "result": result},
    )
    return True, result


def get_active_challenges(db: Session, user_id: int) -> list[MFAChallenge]:
    """Return all non-expired, non-used challenges for a user."""
    return (
        db.query(MFAChallenge)
        .filter(
            MFAChallenge.user_id == user_id,
            MFAChallenge.used == False,
            MFAChallenge.expires_at > datetime.utcnow(),
        )
        .order_by(MFAChallenge.issued_at.desc())
        .all()
    )
