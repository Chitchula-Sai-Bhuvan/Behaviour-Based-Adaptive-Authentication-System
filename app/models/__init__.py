"""
models/__init__.py
──────────────────
Import every ORM model so that Base.metadata registers all 7 tables.
"""

from app.models.user import User
from app.models.auth_event import AuthEvent, EventType
from app.models.risk_decision import RiskDecision, Decision
from app.models.mfa_challenge import MFAChallenge
from app.models.revoked_token import RevokedToken
from app.models.trusted_device import TrustedDevice
from app.models.login_session import LoginSession

__all__ = [
    "User", "AuthEvent", "EventType",
    "RiskDecision", "Decision",
    "MFAChallenge", "RevokedToken",
    "TrustedDevice", "LoginSession",
]
