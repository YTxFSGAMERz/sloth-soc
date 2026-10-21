"""Ensemble detector combining rules, statistical tail tests, and unsupervised ML."""

from __future__ import annotations

import numpy as np
import pandas as pd
from scipy.stats import rankdata

from sloth_soc.config import SlothSocConfig
from sloth_soc.detectors.iforest import IsolationForestDetector
from sloth_soc.detectors.rules import RuleDetector
from sloth_soc.detectors.stat import StatDetector
from sloth_soc.detectors.tabpfn_det import TabPFNDetector


class EnsembleDetector:
    """Ensemble detector combining rules, Poisson statistics, and Isolation Forest."""

    def __init__(self, config: SlothSocConfig | None = None, seed: int = 42) -> None:
        self.config = config or SlothSocConfig()
        self.seed = seed
        self.rules = RuleDetector(self.config.detect.rules)
        self.stat = StatDetector()
        self.iforest = IsolationForestDetector(seed=seed)
        self.tabpfn = TabPFNDetector(seed=seed) if self.config.detect.tabpfn.enabled else None

    def fit(self, X: pd.DataFrame, y: pd.Series | None = None) -> None:
        """Fit statistical and machine learning components."""
        self.rules.fit(X, y)
        self.stat.fit(X, y)
        self.iforest.fit(X, y)
        if self.tabpfn and self.tabpfn.available:
            self.tabpfn.fit(X, y)

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Compute ensemble rank-average anomaly score in [0, 1]."""
        if X.empty:
            return np.array([])

        scores_to_average: list[np.ndarray] = []

        # 1. Rule scores
        rule_scores = self.rules.score(X)

        # 2. Statistical tail scores
        stat_scores = self.stat.score(X)
        if len(stat_scores) > 1:
            stat_ranks = (rankdata(stat_scores) - 1.0) / (len(stat_scores) - 1.0)
            scores_to_average.append(stat_ranks)
        else:
            scores_to_average.append(stat_scores)

        # 3. Isolation Forest percentile ranks
        iforest_scores = self.iforest.score(X)
        scores_to_average.append(iforest_scores)

        # 4. Optional TabPFN
        if self.tabpfn and self.tabpfn.available and self.tabpfn.is_fitted:
            tabpfn_scores = self.tabpfn.score(X)
            scores_to_average.append(tabpfn_scores)

        # Mean rank score across ML/stat detectors
        ml_rank_mean = np.mean(scores_to_average, axis=0)

        # Blend rule severity with ML rank: rule score provides floor
        final_scores = np.maximum(rule_scores, ml_rank_mean)
        return final_scores

    def explain(self, row: pd.Series) -> list[str]:
        """Aggregate explanations across rules, statistical spikes, and ML anomalies."""
        explanations = []
        # Rule explanations first
        explanations.extend(self.rules.explain(row))
        # Stat explanations
        explanations.extend(self.stat.explain(row))
        # Isolation Forest top features
        explanations.extend(self.iforest.explain(row, top_k=2))
        return explanations
