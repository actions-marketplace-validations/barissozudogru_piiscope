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

from pydantic_settings import BaseSettings
from pydantic import Field, validator


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

    # File upload limits
    max_file_size_mb: int = Field(default=2048, env="MAX_FILE_SIZE_MB")
    max_chunk_size: int = Field(default=10000, env="MAX_CHUNK_SIZE")

    # Rate limiting
    rate_limit_per_minute: int = Field(default=100, env="RATE_LIMIT_PER_MINUTE")
    
    # Logging configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    
    # Security headers
    enable_security_headers: bool = Field(default=True, env="ENABLE_SECURITY_HEADERS")
    
    # CORS settings
    cors_origins: str = Field(default="http://localhost:3000,https://localhost:3000", env="CORS_ORIGINS")

    @validator('jwt_secret_key')
    def validate_jwt_secret(cls, v):
        if len(v) < 32:
            raise ValueError('JWT secret key must be at least 32 characters long')
        return v

    @validator('max_file_size_mb')
    def validate_file_size(cls, v):
        if v <= 0 or v > 10240:  # Max 10GB
            raise ValueError('File size must be between 1MB and 10240MB')
        return v

    @validator('log_level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'Log level must be one of: {", ".join(valid_levels)}')
        return v.upper()

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(',')]

    class Config:
        env_file = os.getenv("ENV_FILE", ".env")
        env_file_encoding = "utf-8"

    @property
    def access_token_expires(self) -> timedelta:
        return timedelta(minutes=self.access_token_expire_minutes)


settings = Settings()  # Singleton settings object