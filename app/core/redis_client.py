"""
core/redis_client.py
─────────────────────
Singleton Redis connection pool used across the entire application.

Redis is used for:
  • Rate-limiting counters (TTL-backed, no DB writes)
  • Behaviour monitoring counters (MFA requests, login attempts, approvals)
  • MFA challenge existence checks (fast O(1) lookup before hitting MySQL)
  • Revoked JTI blacklist cache (avoids a DB hit on every authenticated request)

If Redis is unavailable the application falls back gracefully — behaviour
counters are read from MySQL and revocation checks are stricter (DB-only).
"""

import logging
import time
from typing import Optional

import redis
from redis.exceptions import ConnectionError as RedisConnectionError, TimeoutError as RedisTimeoutError

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Connection pool ────────────────────────────────────────────────────────────
_pool: Optional[redis.ConnectionPool] = None

# ── Failure back-off: don't retry for 30 s after a failure ────────────────────
_redis_unavailable_until: float = 0.0


def get_pool() -> redis.ConnectionPool:
    global _pool
    if _pool is None:
        _pool = redis.ConnectionPool.from_url(
            settings.REDIS_URL,
            max_connections=20,
            decode_responses=True,       # always return str, not bytes
            socket_connect_timeout=0.5,  # fast fail when Redis is not running
            socket_timeout=0.5,
        )
    return _pool


def get_redis() -> Optional[redis.Redis]:
    """
    Return a Redis client, or None if the server is unreachable.
    Callers should handle None and fall back to MySQL-based logic.
    Uses a 30-second back-off so a single unavailability doesn't
    generate a 0.5 s penalty on every single call within the request.
    """
    global _redis_unavailable_until
    if time.monotonic() < _redis_unavailable_until:
        return None          # still in back-off window — skip the ping
    try:
        client = redis.Redis(connection_pool=get_pool())
        client.ping()
        return client
    except (RedisConnectionError, RedisTimeoutError, OSError):
        _redis_unavailable_until = time.monotonic() + 30.0
        logger.warning("Redis unavailable — falling back to DB-only mode.")
        return None


# ── Typed helpers ──────────────────────────────────────────────────────────────

class RedisCounters:
    """
    Namespace for all Redis counter operations.

    Key naming convention:
        {prefix}:{user_id}  →  integer counter with TTL
    """

    PREFIX_MFA_REQ   = "mfa_req"
    PREFIX_LOGIN_ATT = "login_att"
    PREFIX_APPROVAL  = "approval"
    PREFIX_JTI_BLOCK = "revoked_jti"

    def __init__(self, client: redis.Redis):
        self._r = client

    # ── Increment + TTL ────────────────────────────────────────────
    def increment(self, prefix: str, user_id: int, ttl_seconds: int) -> int:
        """Atomic increment; set TTL only on first write."""
        key = f"{prefix}:{user_id}"
        pipe = self._r.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl_seconds, nx=True)   # nx=True: only set TTL if not already set
        results = pipe.execute()
        return int(results[0])

    def get_count(self, prefix: str, user_id: int) -> int:
        key = f"{prefix}:{user_id}"
        val = self._r.get(key)
        return int(val) if val else 0

    # ── JTI revocation cache ───────────────────────────────────────
    def revoke_jti(self, jti: str, ttl_seconds: int) -> None:
        """Mark a JWT ID as revoked for the remainder of its TTL."""
        self._r.setex(f"{self.PREFIX_JTI_BLOCK}:{jti}", ttl_seconds, "1")

    def is_jti_revoked(self, jti: str) -> bool:
        return bool(self._r.exists(f"{self.PREFIX_JTI_BLOCK}:{jti}"))

    # ── MFA challenge cache ────────────────────────────────────────
    def cache_challenge(self, challenge_id: str, user_id: int, ttl_seconds: int) -> None:
        self._r.setex(f"mfa_challenge:{challenge_id}", ttl_seconds, str(user_id))

    def challenge_exists(self, challenge_id: str) -> bool:
        return bool(self._r.exists(f"mfa_challenge:{challenge_id}"))

    def invalidate_challenge(self, challenge_id: str) -> None:
        self._r.delete(f"mfa_challenge:{challenge_id}")
