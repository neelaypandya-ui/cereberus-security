"""IOC model — Indicators of Compromise."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_type: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # ip, domain, url, hash, email
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    tags_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    context_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    feed_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
