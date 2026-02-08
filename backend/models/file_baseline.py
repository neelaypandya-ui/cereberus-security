"""File Baseline model — persists file integrity baselines across restarts."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, func, Index
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class FileBaseline(Base):
    __tablename__ = "file_baselines"
    __table_args__ = (
        Index("ix_file_baselines_path", "file_path", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, onupdate=func.now(), nullable=True
    )
