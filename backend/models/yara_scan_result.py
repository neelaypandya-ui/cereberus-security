"""YaraScanResult model — scan match history (table 34)."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class YaraScanResult(Base):
    """Records of YARA scan matches — Bond's engagement log."""

    __tablename__ = "yara_scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)  # file, directory, process, buffer
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(200), nullable=False)
    rule_namespace: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    strings_matched_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    file_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    triggered_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # manual, integrity, sword
