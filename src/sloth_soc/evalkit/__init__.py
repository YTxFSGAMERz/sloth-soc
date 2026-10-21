"""Evaluation kit: metrics, bootstrap confidence intervals, and experiment runners."""

from sloth_soc.evalkit.figures import generate_all_evaluation_figures
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
    run_experiment_e3,
    run_experiment_e5,
    run_experiment_e6,
)

__all__ = [
    "build_split_dataframe",
    "cluster_bootstrap_ci",
    "compute_binary_metrics",
    "compute_per_scenario_recall",
    "compute_precision_recall_at_k",
    "generate_all_evaluation_figures",
    "get_environment_info",
    "run_experiment_e1",
    "run_experiment_e1b",
    "run_experiment_e2",
    "run_experiment_e3",
    "run_experiment_e5",
    "run_experiment_e6",
]
