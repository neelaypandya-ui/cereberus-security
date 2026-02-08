"""Burned (revoked) JWT token model — persists across server restarts."""

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class BurnedToken(Base):
    __tablename__ = "burned_tokens"
    __table_args__ = (
        Index("ix_burned_tokens_hash", "token_hash", unique=True),
        Index("ix_burned_tokens_expires", "expires_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    burned_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
