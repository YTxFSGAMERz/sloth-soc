"""Unsupervised Isolation Forest anomaly detector with robust scaling and percentile ranking."""

from __future__ import annotations

import numpy as np
import pandas as pd
from scipy.stats import rankdata
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from sloth_soc.schema import FeatureRow


class IsolationForestDetector:
    """Unsupervised anomaly detector using Isolation Forest on robustly scaled features."""

    def __init__(self, n_estimators: int = 300, seed: int = 42) -> None:
        self.seed = seed
        self.n_estimators = n_estimators
        self.scaler = RobustScaler()
        self.model = IsolationForest(
            n_estimators=n_estimators,
            random_state=seed,
            contamination="auto",
        )
        self.is_fitted = False
        self.feature_names = FeatureRow.ml_feature_names()
        self.medians: dict[str, float] = {}
        self.mads: dict[str, float] = {}

    def _extract_ml_matrix(self, X: pd.DataFrame) -> pd.DataFrame:
        """Filter and align numeric ML columns, strictly omitting identifiers."""
        cols = [c for c in self.feature_names if c in X.columns]
        return X[cols].fillna(0.0)

    def fit(self, X: pd.DataFrame, y: pd.Series | None = None) -> None:
        """Fit scaler and Isolation Forest on training/baseline days."""
        if X.empty:
            return

        ml_df = self._extract_ml_matrix(X)
        if ml_df.empty:
            return

        # Record baseline medians and MAD for explanations
        for col in ml_df.columns:
            vals = ml_df[col].values
            med = float(np.median(vals))
            mad = float(np.median(np.abs(vals - med)))
            self.medians[col] = med
            self.mads[col] = max(1e-4, mad)

        scaled_X = self.scaler.fit_transform(ml_df)
        self.model.fit(scaled_X)
        self.is_fitted = True

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Return percentile rank anomaly score [0, 1] (higher = more anomalous)."""
        if not self.is_fitted or X.empty:
            return np.zeros(len(X), dtype=float)

        ml_df = self._extract_ml_matrix(X)
        scaled_X = self.scaler.transform(ml_df)

        # score_samples returns negative anomaly score: more negative = more anomalous
        # Invert so higher number = more anomalous
        raw_anomaly = -self.model.score_samples(scaled_X)

        # Convert to percentile rank in [0, 1]
        ranks = rankdata(raw_anomaly)
        percentiles = (ranks - 1.0) / max(1.0, len(ranks) - 1.0)
        return percentiles

    def explain(self, row: pd.Series, top_k: int = 3) -> list[str]:
        """Explain top anomalous features using robust z-score vs baseline median."""
        if not self.is_fitted:
            return []

        z_scores = []
        for col, med in self.medians.items():
            val = float(row.get(col, 0.0))
            mad = self.mads.get(col, 1.0)
            z = (val - med) / mad
            if z > 2.0:  # Notably above baseline
                z_scores.append((col, val, med, z))

        z_scores.sort(key=lambda x: x[3], reverse=True)
        explanations = []
        for col, val, med, z in z_scores[:top_k]:
            explanations.append(
                f"IsolationForest top anomaly: {col}={val:.1f} (baseline median={med:.1f}, robust z={z:.1f})"
            )

        return explanations
