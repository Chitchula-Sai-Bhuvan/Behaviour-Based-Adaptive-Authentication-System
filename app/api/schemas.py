"""
api/schemas.py
──────────────
Pydantic v2 request/response models for all API endpoints.
All schemas are intentionally separate from ORM models to prevent
accidental leakage of sensitive fields (password_hash, chain_hash, etc.).
"""

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, Field, field_validator


# ── Auth ───────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64,
                          pattern=r"^[a-zA-Z0-9_\-]+$",
                          description="Alphanumeric, underscores, and hyphens only")
    password: str = Field(..., min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    id: int
    username: str
    created_at: datetime
    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: int
    username: str
    session_id: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    session_id: str


# ── MFA ────────────────────────────────────────────────────────────────────────

class MFARequestResponse(BaseModel):
    message: str
    user_id: int
    challenge_id: str     # UUID the client must echo on respond


class MFARespondRequest(BaseModel):
    user_id: int
    challenge_id: str     # must match an active, unused challenge
    approved: bool
    ip_address: Optional[str] = "127.0.0.1"
    device_info: Optional[str] = None


class MFARespondResponse(BaseModel):
    message: str
    event_type: str
    risk_decision: str
    risk_score: int
    triggered_signals: List[str]


# ── Risk ───────────────────────────────────────────────────────────────────────

class RiskEvaluationResponse(BaseModel):
    user_id: int
    triggered_signals: List[str]
    risk_score: int
    decision: str
    reason: str
    decision_id: int


# ── Logs ───────────────────────────────────────────────────────────────────────

class AuthEventOut(BaseModel):
    event_id: int
    user_id: int
    event_type: str
    ip_address: str
    device_info: Optional[str]
    device_fingerprint: Optional[str]
    session_id: Optional[str]
    success: bool
    timestamp: datetime
    model_config = {"from_attributes": True}


class RiskDecisionOut(BaseModel):
    decision_id: int
    user_id: int
    risk_score: int
    decision: str
    reason: str
    timestamp: datetime
    model_config = {"from_attributes": True}


# ── Devices ────────────────────────────────────────────────────────────────────

class TrustedDeviceOut(BaseModel):
    id: int
    device_fingerprint: str
    device_label: Optional[str]
    first_seen_at: datetime
    last_seen_at: datetime
    is_active: bool
    model_config = {"from_attributes": True}


# ── Sessions ───────────────────────────────────────────────────────────────────

class LoginSessionOut(BaseModel):
    session_id: str
    user_id: int
    ip_address: str
    created_at: datetime
    last_active_at: datetime
    is_active: bool
    terminated_reason: Optional[str]
    model_config = {"from_attributes": True}


# ── Audit ──────────────────────────────────────────────────────────────────────

class ChainVerifyResponse(BaseModel):
    user_id: int
    valid: bool
    events_checked: int
    broken_at_event_id: Optional[int] = None
