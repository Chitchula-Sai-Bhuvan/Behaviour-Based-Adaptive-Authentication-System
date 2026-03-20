"""
api/risk.py
────────────
GET /api/risk/evaluate?user_id=N  — run full pipeline, return result
GET /api/risk/audit?user_id=N     — verify audit chain integrity
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.security import compute_device_fingerprint
from app.models.user import User
from app.services.decision_controller import run_evaluation
from app.services.audit_logger import verify_chain
from app.api.schemas import RiskEvaluationResponse, ChainVerifyResponse

router = APIRouter(tags=["Risk Engine"])


@router.get(
    "/evaluate",
    response_model=RiskEvaluationResponse,
    summary="Evaluate risk score for a user based on recent behaviour",
)
def evaluate_risk(
    user_id: int,
    request: Request,
    session_id: str = "",
    db: Session = Depends(get_db),
):
    """
    Run all 7 behavioural signal checks + risk scoring for the given user.
    Device fingerprint and IP are extracted from the live request headers
    to power signals 4 (new_device), 5 (ip_change), and 6 (impossible_travel).
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    ip   = request.client.host if request.client else "unknown"
    ua   = request.headers.get("user-agent", "unknown")
    lang = request.headers.get("accept-language", "")
    fingerprint = compute_device_fingerprint(ip, ua, lang)

    result = run_evaluation(
        db, user_id,
        device_fingerprint=fingerprint,
        ip_address=ip,
        session_id=session_id or None,
    )
    return RiskEvaluationResponse(**result)


@router.get(
    "/audit",
    response_model=ChainVerifyResponse,
    summary="Verify tamper-evident audit chain integrity",
)
def audit_chain(user_id: int, db: Session = Depends(get_db)):
    """
    Recompute every event's chain_hash in ascending event_id order.
    Returns valid=True if the chain is intact, or the first broken event_id.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    result = verify_chain(db, user_id)
    return ChainVerifyResponse(user_id=user_id, **result)
