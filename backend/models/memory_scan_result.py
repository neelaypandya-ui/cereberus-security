"""MemoryScanResult model — memory forensics findings (table 35)."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class MemoryScanResult(Base):
    """Records of memory scanner findings — Bond's reconnaissance log."""

    __tablename__ = "memory_scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    process_name: Mapped[str] = mapped_column(String(200), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(50), nullable=False)  # rwx_region, unbacked_exec, injected_dll, shellcode, yara_match
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
