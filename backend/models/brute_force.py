"""Brute Force Event model — stores failed login attempts from Windows Event Log."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class BruteForceEvent(Base):
    __tablename__ = "brute_force_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    target_service: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    event_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    event_record_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, unique=True)
