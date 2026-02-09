"""YaraRule model — user-managed YARA rules stored in DB (table 33)."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class YaraRule(Base):
    """User-managed YARA rules for Bond's Q-Branch arsenal."""

    __tablename__ = "yara_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_source: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, onupdate=func.now(), nullable=True)
    tags_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    match_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_match_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
