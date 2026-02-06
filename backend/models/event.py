"""Event model."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    module_source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    data_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vpn_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    interface_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
