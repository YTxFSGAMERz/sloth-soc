"""Base protocol and structures for anomaly detectors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class RuleMatch:
    """Details of a matched deterministic rule."""

    rule_id: str
    severity: str  # info | low | medium | high | critical
    kind: str
    reason: str


class Detector(Protocol):
    """Protocol satisfied by all Sloth SOC detectors."""

    def fit(self, X: pd.DataFrame, y: pd.Series | None = None) -> None:
        """Fit detector on baseline or training features."""
        ...

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Compute anomaly score for each row in X, normalized to [0, 1]."""
        ...

    def explain(self, row: pd.Series) -> list[str]:
        """Provide human-readable explanation strings for an anomalous row."""
        ...
