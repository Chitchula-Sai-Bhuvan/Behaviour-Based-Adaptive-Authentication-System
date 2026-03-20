"""services/__init__.py — business logic layer."""
from app.services.auth_service import (
    create_user, authenticate_user, get_user_by_username, get_user_by_id,
    revoke_token, is_token_revoked,
)
from app.services.audit_logger import log_event, verify_chain
from app.services.mfa_service import issue_challenge, respond_to_challenge
from app.services.device_service import is_device_trusted, trust_device
from app.services.session_service import (
    create_session, get_session, is_session_active,
    terminate_session, terminate_all_user_sessions,
)
from app.services.behaviour_monitor import (
    analyse_behaviour,
    record_mfa_request, record_login_attempt, record_approval,
)
from app.services.risk_engine import calculate_risk_score, determine_decision, evaluate_and_store
from app.services.decision_controller import run_evaluation

__all__ = [
    "create_user", "authenticate_user", "get_user_by_username", "get_user_by_id",
    "revoke_token", "is_token_revoked",
    "log_event", "verify_chain",
    "issue_challenge", "respond_to_challenge",
    "is_device_trusted", "trust_device",
    "create_session", "get_session", "is_session_active",
    "terminate_session", "terminate_all_user_sessions",
    "analyse_behaviour", "record_mfa_request", "record_login_attempt", "record_approval",
    "calculate_risk_score", "determine_decision", "evaluate_and_store",
    "run_evaluation",
]
