"""Authentication and authorization utilities.

This module provides functions and FastAPI dependencies to handle
password hashing, JWT token creation and verification, and role
validation for endpoints.
"""
from __future__ import annotations

from datetime import timedelta
from typing import List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .config import settings
from . import models, schemas, utils
from .database import get_db


# OAuth2 scheme to parse bearer tokens from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def authenticate_user(db: Session, username: str, password: str) -> Optional[models.User]:
    """Verify a user's password and return the User object if valid."""
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        return None
    if not utils.verify_password(password, user.password_hash):
        return None
    return user


def create_access_token_for_user(user: models.User) -> str:
    """Create a JWT token for a given user."""
    token_data = {"sub": user.username, "role": user.role.value}
    return utils.create_access_token(token_data, settings.access_token_expires)


async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> models.User:
    """FastAPI dependency to get the current authenticated user from the token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user


def role_required(*allowed_roles: models.RoleEnum):
    """Return a dependency that ensures the current user has one of the allowed roles."""
    async def dependency(current_user: models.User = Depends(get_current_user)) -> models.User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privileges",
            )
        return current_user

    return Depends(dependency)


async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
) -> schemas.Token:
    """Endpoint handler for /auth/login.  Authenticates a user and returns a JWT."""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token_for_user(user)
    return schemas.Token(access_token=access_token)