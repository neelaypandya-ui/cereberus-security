"""VPN Connection model."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class VPNConnection(Base):
    __tablename__ = "vpn_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # connect, disconnect, reconnect, kill_switch
    provider: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    server_location: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    vpn_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    real_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    interface_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
