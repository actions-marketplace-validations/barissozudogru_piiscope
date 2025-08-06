"""Audit logging helper functions.

This module provides a convenience function for writing entries to the
audit log.  All actions that impact sensitive data or configuration
should call ``log_audit_event`` with the appropriate parameters.
"""
from __future__ import annotations

from typing import Any, Optional
from datetime import datetime

from sqlalchemy.orm import Session

from . import models


def log_audit_event(db: Session, user_id: Optional[int], action: str, target: Optional[str] = None, details: Optional[Any] = None) -> None:
    """Record an event in the audit log.

    Args:
        db: Active database session.
        user_id: ID of the user performing the action (may be ``None`` for
            system actions).
        action: A short string describing the action (e.g. ``"scan_started"``).
        target: Optional string identifying the target object (e.g.
            ``"job:123"`` or ``"profile:42"``).
        details: Arbitrary JSON‑serialisable object with additional
            information about the event.
    """
    entry = models.AuditLog(
        user_id=user_id,
        action=action,
        target=target,
        details=details,
        timestamp=datetime.utcnow(),
    )
    db.add(entry)
    db.commit()