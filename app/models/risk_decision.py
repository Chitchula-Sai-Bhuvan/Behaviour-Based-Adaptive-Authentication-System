"""
models/risk_decision.py
───────────────────────
ORM model for the `risk_decisions` table.

After the risk engine evaluates a user's recent behaviour, it
writes one row here recording the computed score and the final
access decision. This table doubles as an audit trail for
compliance / incident response purposes.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Integer, String, DateTime, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Decision(str, enum.Enum):
    """
    Final access decisions produced by the risk scoring engine.

    ALLOW  – score 0-39  : proceed normally
    VERIFY – score 40-69 : prompt for step-up verification
    BLOCK  – score 70+   : deny access, alert security team
    """
    ALLOW  = "ALLOW"
    VERIFY = "VERIFY"
    BLOCK  = "BLOCK"


class RiskDecision(Base):
    __tablename__ = "risk_decisions"

    decision_id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, index=True
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Numeric risk score (sum of triggered weights)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    # Final decision based on score thresholds
    decision: Mapped[Decision] = mapped_column(SAEnum(Decision), nullable=False)
    # Human-readable explanation of which signals fired
    reason: Mapped[str] = mapped_column(String(512), nullable=False)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # ── Relationships ──────────────────────────────────────────────
    user: Mapped["User"] = relationship("User", back_populates="risk_decisions")  # noqa: F821

    def __repr__(self) -> str:
        return (
            f"<RiskDecision id={self.decision_id} user_id={self.user_id} "
            f"score={self.risk_score} decision={self.decision}>"
        )
