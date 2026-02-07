"""AI Model Registry — versioning and rollback for trained models."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class AIModelRegistry(Base):
    __tablename__ = "ai_model_registry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    trained_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    samples_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    epochs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    final_loss: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    metrics_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active"
    )  # active, archived, failed
    is_current: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    config_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
