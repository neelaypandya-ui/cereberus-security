"""Alert model."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_severity_timestamp", "severity", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # critical, high, medium, low, info
    module_source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vpn_status_at_event: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    interface_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    feedback: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # true_positive, false_positive
    feedback_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    feedback_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Phase 12: Alert triage fields
    dismissed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    dismissed_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    dismissed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    snoozed_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    escalated_to_incident_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
