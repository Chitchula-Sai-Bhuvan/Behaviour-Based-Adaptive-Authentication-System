"""
db/session.py
─────────────
SQLAlchemy engine + session factory.
FastAPI dependency `get_db` yields a per-request session and
guarantees it is closed when the request ends (even on error).
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

from app.core.config import settings

# ── Engine ─────────────────────────────────────────────────────────────────────
# pool_pre_ping=True: test connections before use to recover from timeouts.
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=settings.DEBUG,   # log SQL when DEBUG=True
)

# ── Session Factory ────────────────────────────────────────────────────────────
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)


# ── FastAPI Dependency ─────────────────────────────────────────────────────────
def get_db() -> Generator[Session, None, None]:
    """
    Dependency injected into route handlers.
    Usage:
        @router.get("/example")
        def example(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
