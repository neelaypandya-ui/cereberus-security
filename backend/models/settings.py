"""Settings, NetworkTraffic, FileIntegrityBaseline, EmailThreat, Vulnerability, ModuleStatus models."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class NetworkTraffic(Base):
    __tablename__ = "network_traffic"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    bytes_recv: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    interface: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    vpn_routed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    geo_country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    flagged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class FileIntegrityBaseline(Base):
    __tablename__ = "file_integrity_baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    last_verified: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    status: Mapped[str] = mapped_column(String(50), default="verified", nullable=False)


class EmailThreat(Base):
    __tablename__ = "email_threats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    sender: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    indicators_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verdict: Mapped[str] = mapped_column(String(50), default="clean", nullable=False)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(100), nullable=False)
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity_cvss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False)


class ModuleStatus(Base):
    __tablename__ = "module_status"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    module_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    health_status: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False)
    last_heartbeat: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    config_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class Settings(Base):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(50), default="general", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )
