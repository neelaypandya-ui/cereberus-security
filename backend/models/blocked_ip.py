"""Blocked IP model."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    module_source: Mapped[str] = mapped_column(String(100), nullable=False)
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    permanent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    interface: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
