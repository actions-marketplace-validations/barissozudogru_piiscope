"""Utility functions for security, encryption and common helpers."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from jose import jwt
from passlib.context import CryptContext
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import settings
from .exceptions import ConfigurationError


# Password hashing context (bcrypt with stronger settings)
pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    bcrypt__rounds=12  # Increase rounds for better security
)


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt with strong settings."""
    if not password:
        raise ValueError("Password cannot be empty")
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    if not plain_password or not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)


def generate_secure_random_string(length: int = 32) -> str:
    """Generate a cryptographically secure random string."""
    return secrets.token_urlsafe(length)


def generate_api_key() -> str:
    """Generate a secure API key."""
    return f"pk_{generate_secure_random_string(32)}"


def hash_sensitive_data(data: str, salt: Optional[bytes] = None) -> tuple[str, bytes]:
    """Hash sensitive data with a salt for storage."""
    if salt is None:
        salt = os.urandom(32)
    
    # Use PBKDF2 for hashing sensitive data
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    hashed = kdf.derive(data.encode('utf-8'))
    return base64.urlsafe_b64encode(hashed).decode('utf-8'), salt


def create_access_token(data: Dict[str, Any], expires_delta: timedelta) -> str:
    """Create a JWT access token containing the given data.

    :param data: Dictionary of claims to include in the token.
    :param expires_delta: Token validity period.
    :return: Encoded JWT string.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def encrypt_bytes(data: bytes) -> bytes:
    """Encrypt data using AES‑GCM with a key from configuration.

    The encryption key must be a 32‑byte string when decoded from
    base64.  A random 12‑byte nonce is prepended to the ciphertext.
    """
    try:
        key = base64.urlsafe_b64decode(settings.encryption_key)
        if len(key) != 32:
            raise ConfigurationError("Encryption key must be exactly 32 bytes when base64 decoded")
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    except Exception as e:
        raise ConfigurationError(f"Failed to encrypt data: {str(e)}")


def decrypt_bytes(data: bytes) -> bytes:
    """Decrypt data encrypted with `encrypt_bytes`.

    Expects the nonce to be prepended to the ciphertext.
    """
    try:
        key = base64.urlsafe_b64decode(settings.encryption_key)
        if len(key) != 32:
            raise ConfigurationError("Encryption key must be exactly 32 bytes when base64 decoded")
        
        if len(data) < 12:
            raise ValueError("Encrypted data too short to contain valid nonce")
        
        aesgcm = AESGCM(key)
        nonce = data[:12]
        ciphertext = data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    except Exception as e:
        raise ConfigurationError(f"Failed to decrypt data: {str(e)}")


def secure_compare(a: str, b: str) -> bool:
    """Timing-safe string comparison."""
    return secrets.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


def sanitize_for_log(data: str, max_length: int = 100) -> str:
    """Sanitize data for safe logging (remove sensitive info, truncate)."""
    # Remove potential sensitive patterns
    import re
    
    # Remove email-like patterns
    data = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', data)
    
    # Remove phone-like patterns
    data = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', data)
    
    # Remove SSN-like patterns
    data = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]', data)
    
    # Truncate if too long
    if len(data) > max_length:
        data = data[:max_length] + "..."
    
    return data


def validate_file_hash(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Validate file integrity using hash comparison."""
    hash_func = getattr(hashlib, algorithm, None)
    if not hash_func:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hasher = hash_func()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    
    return secure_compare(hasher.hexdigest(), expected_hash)


def read_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_file(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)