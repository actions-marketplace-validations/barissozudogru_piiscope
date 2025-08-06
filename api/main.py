"""FastAPI application entrypoint.

This module initialises the FastAPI app, registers API routers and sets up
middleware such as CORS.  All routes are prefixed under ``/`` and use
dependencies defined in other modules for authentication and role‑based
access control.  To run the API with uvicorn, use

.. code-block:: bash

    uvicorn gdpr_privacy_app.api.main:app --host 0.0.0.0 --port 8000

The API exposes OpenAPI documentation at ``/docs`` and ``/redoc``.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models, database
from .routes import auth_routes, profile_routes, scan_routes, audit_routes

import os

# Ensure tables are created on startup.  In production one should use
# Alembic migrations, but for a self‑contained example we call create_all().
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="GDPR Privacy Risk Detection API", version="1.0.0")

# Allow local frontend to call the API (adjust origins if needed)
origins = [
    "http://localhost:3000",
    "https://localhost:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers under their respective prefixes
app.include_router(auth_routes.router, prefix="/auth", tags=["auth"])
app.include_router(profile_routes.router, prefix="/profiles", tags=["profiles"])
app.include_router(scan_routes.router, prefix="/scan", tags=["scan"])
app.include_router(audit_routes.router, prefix="/audit", tags=["audit"])


@app.on_event("startup")
def create_default_user() -> None:
    """Ensure a super admin user exists on first startup.

    This helper creates a default super admin account if no users are
    present in the database.  The username/password are read from
    environment variables ``DEFAULT_ADMIN_USER`` and ``DEFAULT_ADMIN_PASSWORD``.
    If those are not set, defaults of ``admin``/``admin`` are used.
    """
    db = database.SessionLocal()
    try:
        if db.query(models.User).count() == 0:
            username = os.getenv("DEFAULT_ADMIN_USER", "admin")
            password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin")
            from .utils import get_password_hash

            user = models.User(
                username=username,
                password_hash=get_password_hash(password),
                role=models.RoleEnum.SUPER_ADMIN,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
    finally:
        db.close()