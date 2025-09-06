"""Core detection engine for sensitive data discovery.

The engine combines rule‑based regular expressions, dictionary look‑ups
and optional NLP models to flag potentially sensitive information.
It operates on rows of data provided by a streaming parser.  Findings
are yielded one row at a time to avoid loading entire datasets into
memory.
"""
from __future__ import annotations

import csv
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import pandas as pd
from pandas.io.json._json import JsonReader

try:
    import pyarrow.parquet as pq  # type: ignore
except ImportError:
    pq = None  # Parquet support optional

try:
    import spacy
    from spacy.language import Language
except ImportError:
    spacy = None
    Language = None  # type: ignore

from .regex_patterns import PATTERNS, PatternDefinition
from .dictionaries import GIVEN_NAMES, HOSPITAL_NAMES, DRUG_NAMES


logger = logging.getLogger(__name__)


@dataclass
class Finding:
    record_index: int
    column_name: str
    rule_id: str
    severity: float
    confidence: float
    evidence: str


class DetectionEngine:
    def __init__(self, profile: Dict[str, Any]):
        """Initialise the detection engine from a profile definition.

        :param profile: A dictionary containing optional keys:
            - patterns: mapping of rule ID to severity overrides.
            - dictionaries: enabling/disabling specific dictionaries.
            - model: model configuration (use_spacy: bool).
        """
        self.profile = profile or {}
        self.patterns: Dict[str, PatternDefinition] = PATTERNS.copy()
        # Apply severity overrides from the profile
        for rule_id, spec in self.profile.get("patterns", {}).items():
            if rule_id in self.patterns and "severity" in spec:
                self.patterns[rule_id].severity = float(spec["severity"])
        # Dictionary settings
        dict_cfg = self.profile.get("dictionaries", {})
        self.use_name_dict = dict_cfg.get("names", {}).get("enabled", True)
        self.use_hospital_dict = dict_cfg.get("hospitals", {}).get("enabled", True)
        self.use_drug_dict = dict_cfg.get("drugs", {}).get("enabled", True)
        # NLP model
        model_cfg = self.profile.get("model", {})
        self.use_spacy = bool(model_cfg.get("use_spacy", False)) and spacy is not None
        self.nlp: Optional[Language] = None
        if self.use_spacy:
            try:
                self.nlp = spacy.load(model_cfg.get("model_name", "en_core_web_sm"))
            except Exception as e:
                logger.warning("Failed to load spaCy model: %s", e)
                self.use_spacy = False

    def detect_cell(self, value: str, column_name: str) -> List[Finding]:
        """Detect sensitive information in a single cell.

        :param value: The cell value as a string.
        :param column_name: Name of the column (for context).
        :return: A list of findings for this cell.
        """
        findings: List[Finding] = []
        text = str(value).strip()
        if not text:
            return findings
        record_index_placeholder = 0  # placeholder; actual index is set later
        # Regex patterns
        for rule_id, pattern_def in self.patterns.items():
            if pattern_def.pattern.search(text):
                confidence = 0.9  # high confidence for regex match
                findings.append(
                    Finding(
                        record_index=record_index_placeholder,
                        column_name=column_name,
                        rule_id=rule_id,
                        severity=pattern_def.severity,
                        confidence=confidence,
                        evidence=text[:200],
                    )
                )
        lower = text.lower()
        # Dictionary look‑ups
        # Names
        if self.use_name_dict:
            tokens = lower.split()
            for token in tokens:
                if token in GIVEN_NAMES:
                    findings.append(
                        Finding(
                            record_index=record_index_placeholder,
                            column_name=column_name,
                            rule_id="given_name",
                            severity=0.3,
                            confidence=0.6,
                            evidence=token,
                        )
                    )
                    break
        # Hospitals
        if self.use_hospital_dict:
            for h in HOSPITAL_NAMES:
                if h in lower:
                    findings.append(
                        Finding(
                            record_index=record_index_placeholder,
                            column_name=column_name,
                            rule_id="hospital_name",
                            severity=0.4,
                            confidence=0.7,
                            evidence=h,
                        )
                    )
                    break
        # Drugs
        if self.use_drug_dict:
            for d in DRUG_NAMES:
                if d in lower:
                    findings.append(
                        Finding(
                            record_index=record_index_placeholder,
                            column_name=column_name,
                            rule_id="drug_name",
                            severity=0.5,
                            confidence=0.7,
                            evidence=d,
                        )
                    )
                    break
        # spaCy NER
        if self.use_spacy and self.nlp:
            doc = self.nlp(text)
            for ent in doc.ents:
                # We consider PERSON, LOCATION, ORGANISATION as potentially sensitive
                if ent.label_ in {"PERSON", "GPE", "ORG", "LOC", "DATE", "CARDINAL"}:
                    severity = 0.3 if ent.label_ == "PERSON" else 0.2
                    confidence = 0.5
                    findings.append(
                        Finding(
                            record_index=record_index_placeholder,
                            column_name=column_name,
                            rule_id=f"ner_{ent.label_.lower()}",
                            severity=severity,
                            confidence=confidence,
                            evidence=ent.text,
                        )
                    )
        return findings

    def scan_row(self, row: Dict[str, Any], record_index: int) -> List[Finding]:
        """Scan a dictionary representing a row and return findings.

        The record_index is stored on each finding for later retrieval.
        """
        all_findings: List[Finding] = []
        for col_name, value in row.items():
            cell_findings = self.detect_cell(value, col_name)
            for f in cell_findings:
                f.record_index = record_index
                all_findings.append(f)
        return all_findings

    def scan_csv(self, file_path: str, callback: Callable[[int, List[Finding]], None], *, chunksize: int = 1000) -> None:
        """Scan a CSV file in chunks, invoking callback on each batch of findings.

        :param file_path: Path to the CSV file.
        :param callback: Function called with the record index and list of findings for each row.
        :param chunksize: Number of rows per chunk.
        """
        import time
        start_time = time.time()
        processed_rows = 0
        
        try:
            reader = pd.read_csv(file_path, chunksize=chunksize, dtype=str, keep_default_na=False)
            record_index = 0
            
            for chunk in reader:
                chunk_start = time.time()
                chunk_findings = 0
                
                for _, row in chunk.iterrows():
                    row_dict = row.to_dict()
                    findings = self.scan_row(row_dict, record_index)
                    if findings:
                        callback(record_index, findings)
                        chunk_findings += len(findings)
                    record_index += 1
                    processed_rows += 1
                
                # Log chunk processing metrics
                chunk_time = time.time() - chunk_start
                logger.debug(f"Processed chunk of {len(chunk)} rows in {chunk_time:.2f}s, found {chunk_findings} findings")
                
        except Exception as e:
            logger.error(f"Error scanning CSV file {file_path}: {str(e)}")
            raise
        finally:
            total_time = time.time() - start_time
            logger.info(f"Completed CSV scan: {processed_rows} rows in {total_time:.2f}s")

    def scan_json(self, file_path: str, callback: Callable[[int, List[Finding]], None]) -> None:
        """Scan a newline‑delimited JSON file (NDJSON).

        Each line should contain a JSON object representing a row.
        """
        record_index = 0
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    findings = self.scan_row(obj, record_index)
                    if findings:
                        callback(record_index, findings)
                    record_index += 1

    def scan_parquet(self, file_path: str, callback: Callable[[int, List[Finding]], None], *, batch_size: int = 1000) -> None:
        """Scan a Parquet file using pyarrow in batches."""
        if pq is None:
            raise RuntimeError("pyarrow is not installed; cannot read Parquet files")
        table = pq.read_table(file_path)
        record_index = 0
        df = table.to_pandas()
        for _, row in df.iterrows():
            row_dict = row.to_dict()
            findings = self.scan_row(row_dict, record_index)
            if findings:
                callback(record_index, findings)
            record_index += 1

    def scan_file(self, file_path: str, file_format: str, callback: Callable[[int, List[Finding]], None]) -> None:
        """Dispatch scanning based on file format."""
        file_format = file_format.lower()
        if file_format == "csv":
            self.scan_csv(file_path, callback)
        elif file_format == "json":
            self.scan_json(file_path, callback)
        elif file_format in {"parquet", "parq"}:
            self.scan_parquet(file_path, callback)
        else:
            raise ValueError(f"Unsupported file format: {file_format}")