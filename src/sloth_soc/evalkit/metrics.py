"""Evaluation metrics and bootstrap confidence interval computation."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_fscore_support


def compute_binary_metrics(
    y_true: np.ndarray, y_score: np.ndarray, threshold: float = 0.5
) -> dict[str, float]:
    """Calculate precision, recall, f1, and PR-AUC for binary classification."""
    if len(y_true) == 0:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "pr_auc": 0.0}

    y_true_binary = (y_true == 1).astype(int)
    y_pred = (y_score >= threshold).astype(int)

    # Handle single class edge case
    if len(np.unique(y_true_binary)) < 2:
        pr_auc = 1.0 if y_true_binary[0] == 1 else 0.0
    else:
        try:
            pr_auc = float(average_precision_score(y_true_binary, y_score))
        except Exception:
            pr_auc = 0.0

    p, r, f1, _ = precision_recall_fscore_support(
        y_true_binary, y_pred, average="binary", zero_division=0.0
    )

    return {
        "precision": float(p),
        "recall": float(r),
        "f1": float(f1),
        "pr_auc": float(pr_auc),
    }


def compute_precision_recall_at_k(
    df: pd.DataFrame, score_col: str = "score", k: int = 5
) -> tuple[float, float]:
    """Compute precision@K and recall@K aggregated per (date) group."""
    if df.empty or "date" not in df.columns or "label_binary" not in df.columns:
        return 0.0, 0.0

    precisions = []
    recalls = []

    for _, group in df.groupby("date"):
        total_positives = int(group["label_binary"].sum())
        if total_positives == 0:
            continue

        sorted_group = group.sort_values(by=score_col, ascending=False).head(k)
        retrieved_positives = int(sorted_group["label_binary"].sum())

        precisions.append(retrieved_positives / min(k, len(sorted_group)))
        recalls.append(retrieved_positives / total_positives)

    mean_p = float(np.mean(precisions)) if precisions else 0.0
    mean_r = float(np.mean(recalls)) if recalls else 0.0
    return mean_p, mean_r


def compute_per_scenario_recall(
    df: pd.DataFrame, score_col: str = "score", threshold: float = 0.5
) -> dict[str, float]:
    """Compute recall broken down by scenario code (B1-B6, M1-M7)."""
    if df.empty or "scenario" not in df.columns:
        return {}

    per_scenario = {}
    for scenario, group in df.groupby("scenario"):
        pred_pos = (group[score_col] >= threshold).sum()
        total = len(group)
        per_scenario[scenario] = float(pred_pos / total) if total > 0 else 0.0

    return per_scenario


def cluster_bootstrap_ci(
    df: pd.DataFrame,
    metric_fn,
    cluster_col: str = "date",
    n_resamples: int = 500,
    alpha: float = 0.05,
    seed: int = 42,
) -> tuple[float, float]:
    """Compute cluster bootstrap confidence intervals resampling dates."""
    clusters = df[cluster_col].unique()
    if len(clusters) < 2:
        val = metric_fn(df)
        return val, val

    rng = np.random.default_rng(seed)
    boot_vals = []

    for _ in range(n_resamples):
        resampled_clusters = rng.choice(clusters, size=len(clusters), replace=True)
        sample_df = pd.concat([df[df[cluster_col] == c] for c in resampled_clusters])
        try:
            val = metric_fn(sample_df)
            boot_vals.append(val)
        except Exception:
            pass

    if not boot_vals:
        return 0.0, 0.0

    low = float(np.percentile(boot_vals, 100 * (alpha / 2)))
    high = float(np.percentile(boot_vals, 100 * (1 - alpha / 2)))
    return low, high
