"""Remediation action model — action execution log."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class RemediationAction(Base):
    __tablename__ = "remediation_actions"
    __table_args__ = (
        Index("ix_remediation_actions_incident", "incident_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    playbook_rule_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    action_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # block_ip, kill_process, quarantine_file, isolate_network, disable_user
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    parameters_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending"
    )  # pending, executing, completed, failed, rolled_back
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    result_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    executed_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    rollback_data_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verification_status: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )  # pending_verification, verified, failed_verification, skipped
    verification_result_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    verification_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
