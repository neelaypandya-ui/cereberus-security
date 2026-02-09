"""SwordExecutionLog model — Sword Protocol execution history (table 37)."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class SwordExecutionLog(Base):
    """Execution log for Sword Protocol actions — Bond's engagement record."""

    __tablename__ = "sword_execution_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[int] = mapped_column(Integer, nullable=False)
    codename: Mapped[str] = mapped_column(String(50), nullable=False)
    trigger_event_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    actions_taken_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    result: Mapped[str] = mapped_column(String(30), nullable=False)  # success, partial, failed, rate_limited
    escalation_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    executed_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    duration_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
