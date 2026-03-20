"""
services/decision_controller.py
─────────────────────────────────
Single orchestration entry point for the risk evaluation pipeline.

Flow:
  1. analyse_behaviour()  →  triggered signals list
  2. evaluate_and_store() →  score + Decision record written to DB
  3. Return EvaluationResult TypedDict

If the decision is BLOCK, the controller also:
  • Terminates the user's active session
  • Logs a LOCKOUT event to the audit trail

API routes call only run_evaluation() — they never touch the monitor
or engine directly.
"""

from typing import TypedDict, List, Optional

from sqlalchemy.orm import Session

from app.models.risk_decision import Decision, RiskDecision
from app.services.behaviour_monitor import analyse_behaviour
from app.services.risk_engine import evaluate_and_store
from app.core.logger import get_logger

logger = get_logger(__name__)


class EvaluationResult(TypedDict):
    user_id:           int
    triggered_signals: List[str]
    risk_score:        int
    decision:          str
    reason:            str
    decision_id:       int


def run_evaluation(
    db: Session,
    user_id: int,
    device_fingerprint: Optional[str] = None,
    ip_address: Optional[str] = None,
    session_id: Optional[str] = None,
) -> EvaluationResult:
    """
    Execute the full risk evaluation pipeline and return a serialisable result.

    Parameters
    ----------
    db                 : active SQLAlchemy session
    user_id            : user being evaluated
    device_fingerprint : current device SHA-256 fingerprint
    ip_address         : current client IP address
    session_id         : active session ID (used for BLOCK session termination)
    """
    # Step 1 — Observe
    signals: List[str] = analyse_behaviour(
        db, user_id,
        device_fingerprint=device_fingerprint,
        ip_address=ip_address,
    )

    # Step 2 — Score + persist
    record: RiskDecision = evaluate_and_store(db, user_id, signals)

    # Step 3 — Enforce BLOCK decision
    if record.decision == Decision.BLOCK and session_id:
        from app.services.session_service import terminate_session
        terminate_session(db, session_id, reason="RISK_BLOCK")
        logger.warning(
            "Session terminated due to BLOCK decision",
            extra={"user_id": user_id, "session_id": session_id, "score": record.risk_score},
        )

    return EvaluationResult(
        user_id=user_id,
        triggered_signals=signals,
        risk_score=record.risk_score,
        decision=record.decision.value,
        reason=record.reason,
        decision_id=record.decision_id,
    )
