"""Pydantic models used for request/response validation.

These schemas define the shape of payloads accepted by the API and
returned to clients.  They also serve as documentation in the
auto‑generated OpenAPI spec (Swagger UI).
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, EmailStr, Field

from .models import RoleEnum, ScanStatus


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


class ScanJobCreate(BaseModel):
    profile_id: int
    file_name: str
    # The file itself is uploaded via multipart/form-data; no field here


class ScanJobOut(BaseModel):
    id: int
    profile_id: int
    file_name: str
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