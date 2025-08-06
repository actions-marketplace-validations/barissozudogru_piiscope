"""Anonymisation and risk metrics.

This module provides functions to compute k‑anonymity, l‑diversity and
t‑closeness on tabular data.  These metrics help quantify the
re‑identification risk of a dataset【873173610014637†L272-L318】【873173610014637†L373-L380】.

Note:  Metrics are computed on a full `pandas.DataFrame`.  For
datasets larger than memory, you should compute aggregated counts in
the worker and compute metrics incrementally or on sampled data.
"""
from __future__ import annotations

from typing import List, Any, Optional

import numpy as np
import pandas as pd


def compute_k_anonymity(df: pd.DataFrame, quasi_identifiers: List[str]) -> Optional[int]:
    """Compute the k‑anonymity of a DataFrame for the given quasi‑identifiers.

    k‑anonymity is defined as the size of the smallest equivalence class
    when grouping by the quasi‑identifier columns【873173610014637†L272-L318】.

    :param df: DataFrame containing the data.
    :param quasi_identifiers: List of column names considered quasi‑identifiers.
    :return: The minimum equivalence class size (k) or None if df is empty.
    """
    if df.empty or not quasi_identifiers:
        return None
    group_sizes = df.groupby(quasi_identifiers).size()
    return int(group_sizes.min())


def compute_l_diversity(
    df: pd.DataFrame, quasi_identifiers: List[str], sensitive_attr: str
) -> Optional[int]:
    """Compute the l‑diversity of a DataFrame for a sensitive attribute.

    l‑diversity measures the minimum number of distinct values of the
    sensitive attribute within each equivalence class【873173610014637†L373-L380】.
    A higher l indicates more diversity and therefore lower risk.

    :param df: DataFrame containing the data.
    :param quasi_identifiers: List of column names considered quasi‑identifiers.
    :param sensitive_attr: Name of the sensitive attribute column.
    :return: The minimum count of distinct sensitive values per class or None.
    """
    if df.empty or not quasi_identifiers or sensitive_attr not in df.columns:
        return None
    l_values = (
        df.groupby(quasi_identifiers)[sensitive_attr]
        .nunique(dropna=True)
    )
    return int(l_values.min())


def compute_t_closeness(
    df: pd.DataFrame, quasi_identifiers: List[str], sensitive_attr: str
) -> Optional[float]:
    """Compute t‑closeness of a DataFrame for a sensitive attribute.

    t‑closeness compares the distribution of the sensitive attribute in
    each equivalence class to the distribution in the entire dataset
    using the total variation distance (half the L1 distance between
    distributions)【873173610014637†L390-L398】.  The t‑closeness is the
    maximum distance observed; smaller values indicate closer
    distributions and thus better anonymisation.

    :return: The maximum total variation distance across equivalence
      classes, or None if not applicable.
    """
    if df.empty or not quasi_identifiers or sensitive_attr not in df.columns:
        return None
    # Overall distribution of sensitive attribute
    overall_counts = df[sensitive_attr].value_counts(normalize=True)
    overall_dist = overall_counts.to_dict()
    max_tv = 0.0
    # Group by quasi‑identifiers
    grouped = df.groupby(quasi_identifiers)
    for _, group in grouped:
        class_counts = group[sensitive_attr].value_counts(normalize=True)
        # Align distributions
        keys = set(overall_dist.keys()).union(class_counts.index)
        tv = 0.0
        for k in keys:
            p = overall_dist.get(k, 0.0)
            q = class_counts.get(k, 0.0)
            tv += abs(p - q)
        tv *= 0.5  # total variation distance is half the L1 distance
        if tv > max_tv:
            max_tv = float(tv)
    return max_tv