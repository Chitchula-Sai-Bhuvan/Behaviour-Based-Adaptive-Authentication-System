"""
services/risk_engine.py
────────────────────────
Translates triggered behavioural signals into a numeric risk score,
derives an access decision, and persists the result.

Risk formula:   R = Σ weight(signal) for each triggered signal

Weights (all configurable in .env / settings):
  excess_mfa_requests   → 30  (MFA fatigue — high confidence attack)
  rapid_login_attempts  → 20  (brute-force / credential stuffing)
  repeated_approvals    → 25  (user approving without scrutiny)
  new_device_detected   → 20  (unknown hardware fingerprint)
  ip_change_detected    → 15  (network change mid-session)
  impossible_travel     → 40  (simultaneous login from distant IP)
  off_hours_access      → 10  (outside normal working hours)

Maximum score: 30+20+25+20+15+40+10 = 160 → always BLOCK if all fire.

Decision thresholds:
  0 – 39  → ALLOW
  40 – 69 → VERIFY  (step-up authentication)
  70+     → BLOCK
"""

from datetime import datetime, timezone
from typing import List

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.risk_decision import RiskDecision, Decision
from app.core.logger import get_logger

logger = get_logger(__name__)


def _build_weights() -> dict[str, int]:
    """
    Build the signal-weight map from settings.
    Called once at import time; settings are read from .env.
    The dict is returned (not a module-level global) so it picks up
    any monkey-patching done in tests.
    """
    return {
        "excess_mfa_requests":  settings.WEIGHT_EXCESS_MFA,
        "rapid_login_attempts": settings.WEIGHT_RAPID_LOGIN,
        "repeated_approvals":   settings.WEIGHT_REPEATED_APPROVALS,
        "new_device_detected":  settings.WEIGHT_NEW_DEVICE,
        "ip_change_detected":   settings.WEIGHT_IP_CHANGE,
        "impossible_travel":    settings.WEIGHT_IMPOSSIBLE_TRAVEL,
        "off_hours_access":     settings.WEIGHT_OFF_HOURS,
    }


def calculate_risk_score(triggered_signals: List[str]) -> int:
    """Sum the weights of every triggered signal."""
    weights = _build_weights()
    return sum(weights.get(s, 0) for s in triggered_signals)


def determine_decision(score: int) -> Decision:
    """Map a numeric score to ALLOW / VERIFY / BLOCK."""
    if score <= settings.THRESHOLD_ALLOW:
        return Decision.ALLOW
    elif score <= settings.THRESHOLD_VERIFY:
        return Decision.VERIFY
    else:
        return Decision.BLOCK


def evaluate_and_store(
    db: Session,
    user_id: int,
    triggered_signals: List[str],
) -> RiskDecision:
    """Calculate risk score, persist the decision, and return the ORM object."""
    score = calculate_risk_score(triggered_signals)
    decision = determine_decision(score)

    reason = (
        "Signals triggered: " + ", ".join(triggered_signals)
        if triggered_signals
        else "No anomalous behaviour detected."
    )

    record = RiskDecision(
        user_id=user_id,
        risk_score=score,
        decision=decision,
        reason=reason,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    logger.info(
        "Risk decision stored",
        extra={"user_id": user_id, "score": score, "decision": decision.value, "signals": triggered_signals},
    )
    return record
