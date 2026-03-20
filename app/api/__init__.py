"""api/__init__.py — exposes each router for import in main.py."""
from app.api import auth, mfa, risk, logs, pages

__all__ = ["auth", "mfa", "risk", "logs", "pages"]
