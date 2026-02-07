"""Behavioral Baseline — learned normal patterns per hour/day."""

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class BehavioralBaseline(Base):
    __tablename__ = "behavioral_baselines"
    __table_args__ = (
        UniqueConstraint("metric_name", "hour_of_day", "day_of_week", name="uq_baseline_bucket"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    metric_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    hour_of_day: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-23
    day_of_week: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-6
    mean: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    std: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    min_val: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    max_val: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )
