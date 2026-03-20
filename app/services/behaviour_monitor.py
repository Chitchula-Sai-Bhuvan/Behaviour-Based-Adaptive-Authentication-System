"""
services/behaviour_monitor.py
──────────────────────────────
Advanced behavioural signal detection engine.

Signals (7 total):
  1. excess_mfa_requests   — >3 MFA requests in 2 min             (+30)
  2. rapid_login_attempts  — >5 login attempts in 5 min           (+20)
  3. repeated_approvals    — >3 approvals in 2 min                (+25)
  4. new_device_detected   — fingerprint not in trusted devices   (+20)
  5. ip_change_detected    — different IP than previous session   (+15)
  6. impossible_travel     — login from distant IP within 1h      (+40)
  7. off_hours_access      — login outside 06:00–22:00 local      (+10)

Architecture:
  Redis counters are used for checks 1-3 (hot read path).
  MySQL is the authoritative store and serves as fallback if Redis is down.
  Checks 4-7 are DB + context reads (lower frequency, lower latency impact).
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.redis_client import get_redis, RedisCounters
from app.models.auth_event import AuthEvent, EventType
from app.models.trusted_device import TrustedDevice
from app.core.logger import get_logger

logger = get_logger(__name__)


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _count_events(db: Session, user_id: int, event_type: EventType, window_seconds: int) -> int:
    """Count matching events within a time window — MySQL fallback path."""
    cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
    return (
        db.query(AuthEvent)
        .filter(
            AuthEvent.user_id == user_id,
            AuthEvent.event_type == event_type,
            AuthEvent.timestamp >= cutoff,
        )
        .count()
    )


def _get_redis_count(counters: RedisCounters, prefix: str, user_id: int) -> int:
    return counters.get_count(prefix, user_id)


# ── Signal checks ──────────────────────────────────────────────────────────────

def _check_excess_mfa(db: Session, user_id: int, r_counters: Optional[RedisCounters]) -> bool:
    """Signal 1: More than MFA_REQUEST_LIMIT pushes in the MFA window."""
    if r_counters:
        count = _get_redis_count(r_counters, RedisCounters.PREFIX_MFA_REQ, user_id)
    else:
        count = _count_events(db, user_id, EventType.MFA_REQUEST, settings.MFA_WINDOW_SECONDS)
    return count >= settings.MFA_REQUEST_LIMIT


def _check_rapid_logins(db: Session, user_id: int, r_counters: Optional[RedisCounters]) -> bool:
    """Signal 2: More than LOGIN_ATTEMPT_LIMIT logins in the login window."""
    if r_counters:
        count = _get_redis_count(r_counters, RedisCounters.PREFIX_LOGIN_ATT, user_id)
    else:
        count = _count_events(db, user_id, EventType.LOGIN, settings.LOGIN_WINDOW_SECONDS)
    return count >= settings.LOGIN_ATTEMPT_LIMIT


def _check_repeated_approvals(db: Session, user_id: int, r_counters: Optional[RedisCounters]) -> bool:
    """Signal 3: More than APPROVAL_LIMIT MFA approvals in the approval window."""
    if r_counters:
        count = _get_redis_count(r_counters, RedisCounters.PREFIX_APPROVAL, user_id)
    else:
        count = _count_events(db, user_id, EventType.APPROVE, settings.APPROVAL_WINDOW_SECONDS)
    return count >= settings.APPROVAL_LIMIT


def _check_new_device(db: Session, user_id: int, device_fingerprint: Optional[str]) -> bool:
    """Signal 4: Device fingerprint not in the user's trusted device list."""
    if not device_fingerprint:
        return False
    trusted = (
        db.query(TrustedDevice)
        .filter(
            TrustedDevice.user_id == user_id,
            TrustedDevice.device_fingerprint == device_fingerprint,
            TrustedDevice.is_active == True,
        )
        .first()
    )
    return trusted is None


def _check_ip_change(db: Session, user_id: int, current_ip: Optional[str]) -> bool:
    """
    Signal 5: Login from a different IP than the previous successful session.
    Only fires if there IS a previous session (not on first login).
    """
    if not current_ip:
        return False
    from app.models.user import User
    user = db.get(User, user_id)
    if not user or not user.last_login_ip:
        return False
    # Comparing top-level /24 subnets for IPv4 to avoid false positives from DHCP
    prev_parts = user.last_login_ip.split(".")
    curr_parts = current_ip.split(".")
    if len(prev_parts) == 4 and len(curr_parts) == 4:
        return prev_parts[:3] != curr_parts[:3]
    return user.last_login_ip != current_ip


def _check_impossible_travel(db: Session, user_id: int, current_ip: Optional[str]) -> bool:
    """
    Signal 6: A login using a completely different IP occurred within 1 hour.

    Full geolocation (haversine distance) requires an IP-to-lat/lon service.
    In this implementation we apply a heuristic: if there are TWO logins
    within 60 minutes from IPs that share < 2 octets, we flag it.
    This catches the common case of a credential being used simultaneously
    from geographically distant locations without requiring an external API.
    """
    if not current_ip:
        return False
    cutoff = datetime.utcnow() - timedelta(hours=1)
    recent_logins = (
        db.execute(
            select(AuthEvent.ip_address, AuthEvent.timestamp)
            .where(
                AuthEvent.user_id == user_id,
                AuthEvent.event_type == EventType.LOGIN,
                AuthEvent.success == True,
                AuthEvent.timestamp >= cutoff,
            )
            .order_by(AuthEvent.timestamp.desc())
            .limit(5)
        )
        .all()
    )

    curr_parts = current_ip.split(".")
    if len(curr_parts) != 4:
        return False

    for row_ip, _ in recent_logins:
        prev_parts = row_ip.split(".")
        if len(prev_parts) != 4:
            continue
        matching_octets = sum(a == b for a, b in zip(curr_parts, prev_parts))
        if matching_octets < 2:  # less than /16 in common → flag
            return True

    return False


def _check_off_hours(current_hour: Optional[int] = None) -> bool:
    """
    Signal 7: Login request is outside normal business hours.

    Uses UTC time. In production, cross-reference the user's timezone
    from their profile for better accuracy.
    """
    hour = current_hour if current_hour is not None else datetime.utcnow().hour
    start = settings.OFF_HOURS_START   # 22 (10 PM)
    end   = settings.OFF_HOURS_END     # 6  (6 AM)
    # Handle midnight wrap-around
    if start > end:
        return hour >= start or hour < end
    return start <= hour < end


# ── Public API ─────────────────────────────────────────────────────────────────

def analyse_behaviour(
    db: Session,
    user_id: int,
    device_fingerprint: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> List[str]:
    """
    Run all 7 behavioural checks and return a list of triggered signal keys.

    Parameters
    ----------
    db                 : active SQLAlchemy session
    user_id            : user being evaluated
    device_fingerprint : SHA-256 hash of the current device (for checks 4)
    ip_address         : current client IP (for checks 5 and 6)

    Returns
    -------
    List[str] : keys of triggered signals (empty = no anomaly)
    """
    triggered: List[str] = []

    # Try Redis for hot counters
    r = get_redis()
    r_counters = RedisCounters(r) if r else None

    if _check_excess_mfa(db, user_id, r_counters):
        triggered.append("excess_mfa_requests")

    if _check_rapid_logins(db, user_id, r_counters):
        triggered.append("rapid_login_attempts")

    if _check_repeated_approvals(db, user_id, r_counters):
        triggered.append("repeated_approvals")

    if _check_new_device(db, user_id, device_fingerprint):
        triggered.append("new_device_detected")

    if _check_ip_change(db, user_id, ip_address):
        triggered.append("ip_change_detected")

    if _check_impossible_travel(db, user_id, ip_address):
        triggered.append("impossible_travel")

    if _check_off_hours():
        triggered.append("off_hours_access")

    if triggered:
        logger.info(
            "Behaviour signals triggered",
            extra={"user_id": user_id, "signals": triggered},
        )

    return triggered


# ── Redis counter incrementors (called by API layer on each event) ─────────────

def record_mfa_request(user_id: int) -> None:
    """Increment MFA request counter in Redis."""
    r = get_redis()
    if r:
        RedisCounters(r).increment(
            RedisCounters.PREFIX_MFA_REQ, user_id, settings.MFA_WINDOW_SECONDS
        )


def record_login_attempt(user_id: int) -> None:
    """Increment login attempt counter in Redis."""
    r = get_redis()
    if r:
        RedisCounters(r).increment(
            RedisCounters.PREFIX_LOGIN_ATT, user_id, settings.LOGIN_WINDOW_SECONDS
        )


def record_approval(user_id: int) -> None:
    """Increment approval counter in Redis."""
    r = get_redis()
    if r:
        RedisCounters(r).increment(
            RedisCounters.PREFIX_APPROVAL, user_id, settings.APPROVAL_WINDOW_SECONDS
        )
