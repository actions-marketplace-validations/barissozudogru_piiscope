"""Dictionary and gazetteer support for the detection engine.

These lists are illustrative; in a real deployment you would load
comprehensive name lists, hospital names and drug catalogues from
external files.  The detection engine can optionally check tokens
against these dictionaries to flag potential sensitive information.
"""
from __future__ import annotations

from typing import Set


# Minimal set of given names; extend with locale‑specific lists.
GIVEN_NAMES: Set[str] = {
    "anna", "anne", "maria", "max", "john", "peter", "laura", "hans",
}

# Minimal set of hospital or clinic names
HOSPITAL_NAMES: Set[str] = {
    "charité", "klinikum", "university hospital", "st mary", "st. mary", "royal infirmary",
}

# Minimal set of drug names
DRUG_NAMES: Set[str] = {
    "aspirin", "ibuprofen", "paracetamol", "acetaminophen", "metformin", "insulin",
}