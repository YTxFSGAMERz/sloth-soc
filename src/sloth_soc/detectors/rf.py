"""Supervised Random Forest detector as a baseline for ML benchmarks."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from sloth_soc.schema import FeatureRow


class RandomForestDetector:
    """Supervised benchmark model using Random Forest on tabular features."""

    def __init__(self, n_estimators: int = 100, seed: int = 42) -> None:
        self.seed = seed
        self.n_estimators = n_estimators
        self.model = RandomForestClassifier(n_estimators=n_estimators, random_state=seed)
        self.is_fitted = False
        self.feature_names = FeatureRow.ml_feature_names()

    def _extract_ml_matrix(self, X: pd.DataFrame) -> pd.DataFrame:
        cols = [c for c in self.feature_names if c in X.columns]
        return X[cols].fillna(0.0)

    def fit(self, X: pd.DataFrame, y: pd.Series | None = None) -> None:
        """Fit Random Forest on labeled training rows."""
        if X.empty or y is None or len(y) == 0:
            return

        ml_df = self._extract_ml_matrix(X)
        binary_y = (y == "malicious").astype(int) if y.dtype == object else y.astype(int)

        # Check if we have both classes
        if len(np.unique(binary_y)) > 1:
            self.model.fit(ml_df, binary_y)
            self.is_fitted = True

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Return predicted probability of malicious class [0, 1]."""
        if not self.is_fitted or X.empty:
            return np.zeros(len(X), dtype=float)

        ml_df = self._extract_ml_matrix(X)
        probs = self.model.predict_proba(ml_df)
        if probs.shape[1] > 1:
            return probs[:, 1]
        return np.zeros(len(X), dtype=float)

    def explain(self, row: pd.Series) -> list[str]:
        if not self.is_fitted:
            return []
        return ["RandomForest predicted probability"]
