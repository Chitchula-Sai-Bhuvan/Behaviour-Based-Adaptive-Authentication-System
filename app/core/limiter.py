"""
core/limiter.py
───────────────
Global SlowAPI rate-limiter instance.

Import `limiter` in main.py to register the middleware, then use
the `@limiter.limit(...)` decorator on any endpoint that needs
rate limiting.

Key limits:
  • POST /api/login        — 10 requests / minute  (brute-force protection)
  • POST /api/register     — 5 requests / minute   (registration spam prevention)
  • POST /api/mfa/*        — 20 requests / minute  (MFA fatigue protection)

Rate-limit key: X-Forwarded-For (first entry) takes precedence over the raw
TCP peer address.  This allows test clients and reverse-proxy deployments to
supply their own IP bucket while still defaulting to the real client address
when no forwarded header is present.
"""

from fastapi import Request
from slowapi import Limiter


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "127.0.0.1"


limiter = Limiter(key_func=_client_ip)
