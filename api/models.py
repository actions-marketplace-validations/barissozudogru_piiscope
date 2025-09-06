"""Database models for the privacy risk detection application.

The models defined here map to tables in PostgreSQL.  See
`docs/architecture.md` for an overview of the schema.  Alembic
migrations can be generated separately if desired.  For simplicity
this project defines the schema programmatically and uses SQLAlchemy
`Base.metadata.create_all()` to create tables on startup.
"""
from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
    Float,
)
from sqlalchemy.orm import relationship

from database import Base


class RoleEnum(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=True)
    password_hash = Column(String(128), nullable=False)
    role = Column(Enum(RoleEnum), default=RoleEnum.USER, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan_jobs = relationship("ScanJob", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


class Profile(Base):
    __tablename__ = "profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    version = Column(String(10), default="1.0")
    description = Column(String(255), nullable=True)
    definition = Column(JSON, nullable=False)  # Stores patterns, dictionaries, weights
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    created_by = relationship("User")
    scan_jobs = relationship("ScanJob", back_populates="profile")


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    profile_id = Column(Integer, ForeignKey("profiles.id"), nullable=False)
    data_source_id = Column(Integer, ForeignKey("data_sources.id"), nullable=True)
    file_name = Column(String(255), nullable=True)  # Optional for external data sources
    file_path = Column(String(512), nullable=True)  # Optional for external data sources
    table_name = Column(String(255), nullable=True)  # For database tables
    query = Column(Text, nullable=True)  # For custom SQL queries
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    progress = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="scan_jobs")
    profile = relationship("Profile", back_populates="scan_jobs")
    data_source = relationship("DataSource", back_populates="scan_jobs")
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")
    metrics = relationship("Metric", back_populates="job", uselist=False, cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="job", cascade="all, delete-orphan")
    masks = relationship("Mask", back_populates="job", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    record_index = Column(Integer, nullable=False)
    column_name = Column(String(100), nullable=False)
    rule_id = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)
    evidence = Column(String(255), nullable=True)

    job = relationship("ScanJob", back_populates="findings")


class Metric(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), unique=True)
    quasi_identifiers = Column(JSON, nullable=True)
    k_anonymity = Column(Integer, nullable=True)
    l_diversity = Column(Integer, nullable=True)
    t_closeness = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    job = relationship("ScanJob", back_populates="metrics")


class Mask(Base):
    __tablename__ = "masks"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    column_name = Column(String(100), nullable=False)
    mask_type = Column(String(50), nullable=False)
    params = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    job = relationship("ScanJob", back_populates="masks")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    html_path = Column(String(512), nullable=False)
    pdf_path = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    job = relationship("ScanJob", back_populates="reports")


class DataSourceType(str, enum.Enum):
    GCP_BIGQUERY = "gcp_bigquery"
    GCP_CLOUD_SQL = "gcp_cloud_sql"
    GCP_SPANNER = "gcp_spanner"
    GCP_FIRESTORE = "gcp_firestore"
    AWS_RDS = "aws_rds"
    AWS_REDSHIFT = "aws_redshift"
    AWS_DYNAMODB = "aws_dynamodb"
    AZURE_SQL = "azure_sql"
    AZURE_COSMOS = "azure_cosmos"
    SAP_HANA = "sap_hana"
    SAP_ASE = "sap_ase"
    ORACLE = "oracle"
    SQL_SERVER = "sql_server"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MONGODB = "mongodb"
    SNOWFLAKE = "snowflake"
    DATABRICKS = "databricks"


class ConnectionStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    TESTING = "testing"


class DataSource(Base):
    __tablename__ = "data_sources"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    source_type = Column(Enum(DataSourceType), nullable=False)
    connection_config = Column(JSON, nullable=False)  # Encrypted connection details
    status = Column(Enum(ConnectionStatus), default=ConnectionStatus.INACTIVE)
    last_tested_at = Column(DateTime, nullable=True)
    test_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User")
    scan_jobs = relationship("ScanJob", back_populates="data_source")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(50), nullable=False)
    target = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="audit_logs")