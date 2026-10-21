"""Statistical anomaly detector using Poisson tail tests and Benjamini-Hochberg FDR control."""

from __future__ import annotations

import numpy as np
import pandas as pd
from scipy.stats import poisson


def benjamini_hochberg(p_values: np.ndarray) -> np.ndarray:
    """Adjust p-values using the Benjamini-Hochberg procedure for False Discovery Rate control."""
    p_values = np.asarray(p_values, dtype=float)
    n = len(p_values)
    if n == 0:
        return np.array([])
    if n == 1:
        return p_values

    order = np.argsort(p_values)
    ranks = np.empty(n, dtype=int)
    ranks[order] = np.arange(1, n + 1)

    p_sorted = p_values[order]
    q_sorted = p_sorted * n / np.arange(1, n + 1)
    # Monotonize in reverse
    q_min = np.minimum.accumulate(q_sorted[::-1])[::-1]
    p_adj = np.clip(q_min, 0.0, 1.0)

    # Invert back to original order
    return p_adj[ranks - 1]


class StatDetector:
    """Poisson rate anomaly detector with Benjamini-Hochberg multiple testing correction."""

    def __init__(self, fdr_q: float = 0.05) -> None:
        self.fdr_q = fdr_q
        self.lam_fail: float = 1.0
        self.lam_404: float = 1.0

    def fit(self, X: pd.DataFrame, y: pd.Series | None = None) -> None:
        """Estimate baseline Poisson parameter lambda from training data."""
        if not X.empty:
            fail_vals = X.get("auth_fail_total", pd.Series([0]))
            h404_vals = X.get("http_total", pd.Series([0])) * X.get(
                "http_404_ratio", pd.Series([0])
            )
            # Use median rate of benign population or overall mean floored at 0.5
            self.lam_fail = max(0.5, float(fail_vals.median()))
            self.lam_404 = max(0.5, float(h404_vals.median()))

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Compute FDR-adjusted Poisson tail probability anomaly scores."""
        if X.empty:
            return np.array([])

        fails = X.get("auth_fail_total", pd.Series([0] * len(X))).values
        total_http = X.get("http_total", pd.Series([0] * len(X))).values
        ratio_404 = X.get("http_404_ratio", pd.Series([0.0] * len(X))).values
        h404s = np.round(total_http * ratio_404).astype(int)

        raw_p_values = np.ones(len(X), dtype=float)

        for i in range(len(X)):
            k_fail = int(fails[i])
            k_404 = int(h404s[i])

            # Survival function sf(k - 1) = P(X >= k)
            p_fail = float(poisson.sf(max(0, k_fail - 1), self.lam_fail)) if k_fail > 0 else 1.0
            p_404 = float(poisson.sf(max(0, k_404 - 1), self.lam_404)) if k_404 > 0 else 1.0

            # Combined Fisher or minimum p-value
            raw_p_values[i] = min(p_fail, p_404)

        adj_p = benjamini_hochberg(raw_p_values)

        # Transform adjusted p-value to score in [0, 1]
        # p_adj = 0.05 -> score ~ 0.26; p_adj = 1e-5 -> score = 1.0
        neg_log = -np.log10(np.clip(adj_p, 1e-5, 1.0))
        scores = np.clip(neg_log / 5.0, 0.0, 1.0)
        return scores

    def explain(self, row: pd.Series) -> list[str]:
        explanations = []
        k_fail = int(row.get("auth_fail_total", 0))
        if k_fail > 0:
            p_val = float(poisson.sf(max(0, k_fail - 1), self.lam_fail))
            if p_val < 0.05:
                explanations.append(
                    f"Statistical spike: auth_fail_total={k_fail} (expected baseline ~{self.lam_fail:.1f}, Poisson p={p_val:.2e})"
                )

        h_total = int(row.get("http_total", 0))
        h_ratio = float(row.get("http_404_ratio", 0.0))
        k_404 = int(round(h_total * h_ratio))
        if k_404 > 0:
            p_val_404 = float(poisson.sf(max(0, k_404 - 1), self.lam_404))
            if p_val_404 < 0.05:
                explanations.append(
                    f"Statistical spike: 404_count={k_404} (expected baseline ~{self.lam_404:.1f}, Poisson p={p_val_404:.2e})"
                )

        return explanations
