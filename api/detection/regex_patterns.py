"""Regular expression patterns for detecting sensitive information.

Patterns are organised by a key (rule ID) and include the compiled
regular expression, a description and a severity weight.  The
severities map roughly to the impact of exposure: high values for
medical identifiers or national IDs, medium for general personal
information, and low for less sensitive fields.
"""
from __future__ import annotations

import re
from typing import Dict, Pattern, Tuple


class PatternDefinition:
    def __init__(self, pattern: str, description: str, severity: float):
        self.pattern: Pattern[str] = re.compile(pattern, re.IGNORECASE)
        self.description = description
        self.severity = severity


# Define patterns; these can be extended or overridden by profiles
PATTERNS: Dict[str, PatternDefinition] = {
    # Email addresses
    "email": PatternDefinition(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        "Email address",
        0.3,
    ),
    # EU phone numbers (simple international and local formats)
    "eu_phone": PatternDefinition(
        r"\b(?:\+\d{1,3}[\s.-]?)?(?:\(0\))?\d{3,4}[\s.-]?\d{5,7}\b",
        "Telephone number",
        0.4,
    ),
    # IBAN (International Bank Account Number)
    "iban": PatternDefinition(
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
        "IBAN",
        0.7,
    ),
    # VAT number (generic EU VAT format: two letters + 8–12 digits)
    "vat": PatternDefinition(
        r"\b[A-Z]{2}\d{8,12}\b",
        "VAT number",
        0.6,
    ),
    # IP address (IPv4)
    "ip_address": PatternDefinition(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "IP address",
        0.4,
    ),
    # URL (basic)
    "url": PatternDefinition(
        r"\bhttps?://[\w.-]+(?:\.[\w.-]+)*(?::\d+)?(?:/[\w./?%&=-]*)?\b",
        "URL",
        0.2,
    ),
    # Date of birth or other dates (dd/mm/yyyy or yyyy-mm-dd)
    "date": PatternDefinition(
        r"\b(?:\d{1,2}[./-]){2}\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b",
        "Date",
        0.2,
    ),
    # Credit card numbers (simple Luhn pattern with 13–19 digits)
    "credit_card": PatternDefinition(
        r"\b(?:\d[ -]*?){13,19}\b",
        "Credit card number",
        0.8,
    ),
    # German national ID (Personalausweisnummer) – alphanumeric, 9 or 10 chars
    "national_id": PatternDefinition(
        r"\b[CFGHJKLMNPRTVWXYZ0-9]{9,10}\b",
        "National ID / Passport",
        0.9,
    ),
}