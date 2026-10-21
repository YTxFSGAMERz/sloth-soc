"""Evaluation kit: metrics, bootstrap confidence intervals, and experiment runners."""

from sloth_soc.evalkit.metrics import (
    cluster_bootstrap_ci,
    compute_binary_metrics,
    compute_per_scenario_recall,
    compute_precision_recall_at_k,
)
from sloth_soc.evalkit.runner import (
    build_split_dataframe,
    get_environment_info,
    run_experiment_e1,
    run_experiment_e1b,
    run_experiment_e2,
)

__all__ = [
    "build_split_dataframe",
    "cluster_bootstrap_ci",
    "compute_binary_metrics",
    "compute_per_scenario_recall",
    "compute_precision_recall_at_k",
    "get_environment_info",
    "run_experiment_e1",
    "run_experiment_e1b",
    "run_experiment_e2",
]
