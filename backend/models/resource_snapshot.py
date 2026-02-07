"""Resource snapshot model for historical resource monitoring data."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class ResourceSnapshot(Base):
    __tablename__ = "resource_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False)
    memory_percent: Mapped[float] = mapped_column(Float, nullable=False)
    memory_used_gb: Mapped[float] = mapped_column(Float, nullable=False)
    memory_total_gb: Mapped[float] = mapped_column(Float, nullable=False)
    disk_percent: Mapped[float] = mapped_column(Float, nullable=False)
    disk_used_gb: Mapped[float] = mapped_column(Float, nullable=False)
    disk_total_gb: Mapped[float] = mapped_column(Float, nullable=False)
    net_bytes_sent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    net_bytes_recv: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alert_triggered: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
