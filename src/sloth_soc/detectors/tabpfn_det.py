"""Optional TabPFN supervised tabular classifier with lazy import and graceful fallback."""

from __future__ import annotations

import numpy as np
import pandas as pd

from sloth_soc.schema import FeatureRow


class TabPFNDetector:
    """Supervised tabular foundation model (TabPFN) with graceful degradation."""

    def __init__(self, model_version: str = "default", seed: int = 42) -> None:
        self.model_version = model_version
        self.seed = seed
        self.available = False
        self.model = None
        self.is_fitted = False
        self.feature_names = FeatureRow.ml_feature_names()

        try:
            from tabpfn import TabPFNClassifier  # type: ignore

            self.model = TabPFNClassifier(random_state=seed)
            self.available = True
        except (ImportError, Exception):
            self.available = False

    def _extract_ml_matrix(self, X: pd.DataFrame) -> pd.DataFrame:
        cols = [c for c in self.feature_names if c in X.columns]
        return X[cols].fillna(0.0)

    def fit(self, X: pd.DataFrame, y: pd.Series | None = None) -> None:
        if not self.available or self.model is None or X.empty or y is None:
            return

        ml_df = self._extract_ml_matrix(X)
        binary_y = (y == "malicious").astype(int) if y.dtype == object else y.astype(int)

        # TabPFN supports small-to-medium dataset sizes (cap at 2000 rows on CPU)
        if len(ml_df) > 2000:
            ml_df = ml_df.iloc[:2000]
            binary_y = binary_y[:2000]

        if len(np.unique(binary_y)) > 1:
            try:
                self.model.fit(ml_df, binary_y)
                self.is_fitted = True
            except Exception:
                self.available = False

    def score(self, X: pd.DataFrame) -> np.ndarray:
        if not self.available or not self.is_fitted or self.model is None or X.empty:
            return np.zeros(len(X), dtype=float)

        ml_df = self._extract_ml_matrix(X)
        try:
            probs = self.model.predict_proba(ml_df)
            if probs.shape[1] > 1:
                return probs[:, 1]
        except Exception:
            pass
        return np.zeros(len(X), dtype=float)

    def explain(self, row: pd.Series) -> list[str]:
        if not self.is_fitted:
            return []
        return ["TabPFN few-shot classifier score"]
