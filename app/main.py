"""
main.py
───────
Production-grade FastAPI application entry point.

Security layers applied:
  1. Secure HTTP headers   (X-Frame-Options, CSP, HSTS, nosniff, etc.)
  2. CORS policy           (restricted to ALLOWED_ORIGINS from .env)
  3. SlowAPI rate-limiter  (per-IP, endpoint-level decorators)
  4. Structured JSON logs  (configure_logging called at startup)
  5. DB auto-migration     (idempotent create_all on every restart)

Run:
    py -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.db.base import Base
from app.db.session import engine
import app.models          # noqa: F401 — registers all 7 ORM models with Base.metadata

from app.api import auth, mfa, risk, logs, pages
from app.core.config import settings
from app.core.limiter import limiter
from app.core.logger import configure_logging, get_logger

logger = get_logger(__name__)


# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(application: FastAPI):
    configure_logging(debug=settings.DEBUG)
    Base.metadata.create_all(bind=engine)
    logger.info("DB tables synchronised", extra={"database": settings.DB_NAME})
    yield
    logger.info("Application shutdown")


# ── FastAPI instance ───────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Behaviour-Based Adaptive Authentication System v2. "
        "7-signal risk engine with MFA fatigue detection, "
        "account lockout, JWT revocation, and tamper-evident audit logs."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Rate-limit state + error handler ──────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ───────────────────────────────────────────────────────────────────────
# Set ALLOWED_ORIGINS in .env, comma-separated. Default: localhost only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "Accept-Language"],
)

# ── Secure HTTP headers ────────────────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]       = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com;"
    )
    if settings.ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
    return response

# ── Routers ────────────────────────────────────────────────────────────────────
app.include_router(pages.router)
app.include_router(auth.router,  prefix="/api")
app.include_router(mfa.router,   prefix="/api/mfa")
app.include_router(risk.router,  prefix="/api/risk")
app.include_router(logs.router,  prefix="/api")


# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
def health():
    """Liveness probe used by load balancers and container orchestrators."""
    return {"status": "ok", "version": "2.0.0", "service": settings.APP_NAME}
