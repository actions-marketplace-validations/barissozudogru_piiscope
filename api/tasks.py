"""Celery tasks for long‑running operations such as scanning files.

Each task receives a job ID, loads the corresponding record from the
database, invokes the detection engine and writes findings back to
the database incrementally.  Metrics are computed at the end and
stored on the `metrics` table.
"""
from __future__ import annotations

import os
import math
import uuid
from datetime import datetime
from typing import Dict, List, Tuple, Any

from celery import Celery
from sqlalchemy.orm import Session

from .config import settings
from . import models
from .database import SessionLocal, engine
from .detection.engine import DetectionEngine, Finding
from .detection.metrics import compute_k_anonymity, compute_l_diversity, compute_t_closeness

import pandas as pd  # type: ignore
import json


celery_app = Celery(__name__, broker=settings.redis_url, backend=settings.redis_url)


@celery_app.task(bind=True)
def scan_file_task(self, job_id: int) -> None:
    """Celery task to scan an uploaded file for sensitive data.

    The task retrieves the job and profile from the database, creates a
    detection engine, streams the file and writes findings and metrics.
    """
    db: Session = SessionLocal()
    try:
        job: models.ScanJob = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
        if not job:
            raise ValueError(f"ScanJob {job_id} not found")
        job.status = models.ScanStatus.RUNNING
        job.started_at = datetime.utcnow()
        db.commit()
        # Load profile definition
        profile = job.profile.definition
        engine_det = DetectionEngine(profile)
        file_path = job.file_path
        file_format = os.path.splitext(file_path)[1].lstrip(".").lower()
        # Aggregators for anonymisation metrics
        qi = profile.get("quasi_identifiers") or []
        sensitive_attr = profile.get("sensitive_attribute")
        qi_counts: Dict[Tuple[Any, ...], int] = {}
        qi_sensitive_values: Dict[Tuple[Any, ...], set] = {}
        sensitive_value_counts: Dict[Any, int] = {}

        # Determine file size for progress (approximate number of lines)
        total_rows = None
        try:
            if file_format == "csv":
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    total_rows = sum(1 for _ in f)
            elif file_format == "json":
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    total_rows = sum(1 for _ in f)
            # Parquet handled separately (rows unknown)
        except Exception:
            total_rows = None

        processed_rows = 0

        def callback(record_index: int, findings: List[Finding]) -> None:
            # Insert findings into DB
            for f in findings:
                db.add(
                    models.Finding(
                        job_id=job.id,
                        record_index=f.record_index,
                        column_name=f.column_name,
                        rule_id=f.rule_id,
                        severity=str(f.severity),
                        confidence=f.confidence,
                        evidence=f.evidence,
                    )
                )
            db.commit()
            # Metrics update
            if qi and sensitive_attr:
                # We will update counts for metrics
                row_values = get_row_values(job.file_path, record_index)
                qi_key = tuple(row_values.get(col) for col in qi)
                qi_counts[qi_key] = qi_counts.get(qi_key, 0) + 1
                # Sensitive attribute
                sens_val = row_values.get(sensitive_attr)
                if sens_val is not None:
                    # per group
                    if qi_key not in qi_sensitive_values:
                        qi_sensitive_values[qi_key] = set()
                    qi_sensitive_values[qi_key].add(sens_val)
                    # overall
                    sensitive_value_counts[sens_val] = sensitive_value_counts.get(sens_val, 0) + 1
            # Update progress
            nonlocal processed_rows
            processed_rows += 1
            if total_rows:
                job.progress = processed_rows / total_rows
                db.commit()

        # Helper to retrieve row values again; for metrics we read row line by line from file
        def get_row_values(file_path: str, index: int) -> Dict[str, Any]:
            # For metrics we need values of quasi identifiers and sensitive attr.  We re‑read the row using pandas; not efficient but acceptable for moderate size.
            # If file is huge, we could maintain the row_dict in closure; omitted for brevity.
            try:
                if file_format == "csv":
                    for i, row in enumerate(pd.read_csv(file_path, chunksize=1, dtype=str, keep_default_na=False)):
                        if i == index:
                            return row.iloc[0].to_dict()
                elif file_format == "json":
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f):
                            if i == index:
                                try:
                                    return json.loads(line)
                                except Exception:
                                    break
                else:
                    return {}
            except Exception:
                return {}
            return {}

        # Perform scanning
        try:
            engine_det.scan_file(file_path, file_format, callback)
            job.status = models.ScanStatus.COMPLETED
        except Exception as exc:
            job.status = models.ScanStatus.FAILED
            job.error_message = str(exc)
        finally:
            job.progress = 1.0
            job.finished_at = datetime.utcnow()
            db.commit()
        # Compute and store metrics if applicable
        if qi and sensitive_attr and total_rows:
            try:
                # Build DataFrame for metrics using aggregators may not be efficient; for demonstration, we read entire file into DataFrame.
                df = None
                if file_format == "csv":
                    df = pd.read_csv(file_path, dtype=str, keep_default_na=False)
                elif file_format == "json":
                    df = pd.read_json(file_path, lines=True, dtype=str)
                if df is not None:
                    k = compute_k_anonymity(df, qi)
                    l = compute_l_diversity(df, qi, sensitive_attr)
                    t = compute_t_closeness(df, qi, sensitive_attr)
                else:
                    k = l = t = None
            except Exception as exc:
                k = l = t = None
            metric = models.Metric(
                job_id=job.id,
                quasi_identifiers=qi,
                k_anonymity=k,
                l_diversity=l,
                t_closeness=t,
            )
            db.add(metric)
            db.commit()
    finally:
        db.close()