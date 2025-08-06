"""Utility functions for security, encryption and common helpers."""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict

from jose import jwt
from passlib.context import CryptContext
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings


# Password hashing context (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


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
    key = base64.urlsafe_b64decode(settings.encryption_key)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_bytes(data: bytes) -> bytes:
    """Decrypt data encrypted with `encrypt_bytes`.

    Expects the nonce to be prepended to the ciphertext.
    """
    key = base64.urlsafe_b64decode(settings.encryption_key)
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def read_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_file(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)