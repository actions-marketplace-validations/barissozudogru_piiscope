"""Application configuration.

This module defines configuration parameters used throughout the API,
worker and detection engine.  Values are loaded from environment
variables with sensible defaults for development.  At runtime you
should supply a `.env` file or real environment variables (see
`deploy/env.example`).
"""
from __future__ import annotations

import os
from datetime import timedelta
from typing import Optional

from pydantic import BaseSettings, Field, validator


class Settings(BaseSettings):
    # Database connection string, e.g. "postgresql+psycopg2://user:pass@db:5432/app"
    database_url: str = Field(..., env="DATABASE_URL")

    # Redis broker URL for Celery
    redis_url: str = Field(..., env="REDIS_URL")

    # Secret key used to sign JWT tokens
    jwt_secret_key: str = Field(..., env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=60 * 8, env="ACCESS_TOKEN_EXPIRE_MINUTES")

    # AES encryption key for encrypting raw files (must be 32 bytes when base64 decoded)
    encryption_key: str = Field(..., env="ENCRYPTION_KEY")

    # Retention period for stored findings/raw data (in hours)
    data_retention_hours: int = Field(default=24, env="DATA_RETENTION_HOURS")

    # Allow outbound network calls (disabled by default)
    allow_egress: bool = Field(default=False, env="ALLOW_EGRESS")

    # TLS certificate and key for serving API over HTTPS (optional)
    tls_cert_file: Optional[str] = Field(default=None, env="TLS_CERT_FILE")
    tls_key_file: Optional[str] = Field(default=None, env="TLS_KEY_FILE")

    class Config:
        env_file = os.getenv("ENV_FILE", ".env")
        env_file_encoding = "utf-8"

    @property
    def access_token_expires(self) -> timedelta:
        return timedelta(minutes=self.access_token_expire_minutes)


settings = Settings()  # Singleton settings object