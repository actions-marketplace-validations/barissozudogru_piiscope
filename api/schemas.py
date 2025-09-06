"""Pydantic models used for request/response validation.

These schemas define the shape of payloads accepted by the API and
returned to clients.  They also serve as documentation in the
auto‑generated OpenAPI spec (Swagger UI).
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, EmailStr, Field

from models import RoleEnum, ScanStatus, DataSourceType, ConnectionStatus


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


class UserBase(BaseModel):
    username: str
    email: Optional[EmailStr] = None


class UserCreate(UserBase):
    password: str
    role: Optional[RoleEnum] = RoleEnum.USER


class UserOut(UserBase):
    id: int
    role: RoleEnum
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class ProfileBase(BaseModel):
    name: str
    version: Optional[str] = "1.0"
    description: Optional[str] = None
    definition: Dict[str, Any] = Field(..., description="Profile definition containing patterns and weights")


class ProfileCreate(ProfileBase):
    pass


class ProfileOut(ProfileBase):
    id: int
    created_at: datetime
    updated_at: datetime
    created_by_id: Optional[int]

    class Config:
        orm_mode = True


# Data Source schemas
class DataSourceBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    source_type: DataSourceType


class DataSourceCreate(DataSourceBase):
    connection_config: Dict[str, Any] = Field(..., description="Connection configuration")


class DataSourceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    connection_config: Optional[Dict[str, Any]] = None


class DataSourceOut(DataSourceBase):
    id: int
    user_id: int
    status: ConnectionStatus
    last_tested_at: Optional[datetime]
    test_error: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class ConnectionTestResult(BaseModel):
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None


class ScanJobCreate(BaseModel):
    profile_id: int
    data_source_id: Optional[int] = None
    file_name: Optional[str] = None
    table_name: Optional[str] = Field(None, description="Database table name to scan")
    query: Optional[str] = Field(None, description="Custom SQL query to scan")


class ScanJobOut(BaseModel):
    id: int
    profile_id: int
    data_source_id: Optional[int]
    file_name: Optional[str]
    table_name: Optional[str]
    query: Optional[str]
    status: ScanStatus
    progress: float
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    error_message: Optional[str]

    class Config:
        orm_mode = True


class FindingOut(BaseModel):
    id: int
    record_index: int
    column_name: str
    rule_id: str
    severity: str
    confidence: float
    evidence: Optional[str]

    class Config:
        orm_mode = True


class MetricOut(BaseModel):
    quasi_identifiers: Optional[List[str]]
    k_anonymity: Optional[int]
    l_diversity: Optional[int]
    t_closeness: Optional[float]

    class Config:
        orm_mode = True


class ReportOut(BaseModel):
    id: int
    html_path: str
    pdf_path: Optional[str]
    created_at: datetime

    class Config:
        orm_mode = True


class MessageResponse(BaseModel):
    message: str