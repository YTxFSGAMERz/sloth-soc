"""Experiment runner for benchmarks E1, E1b, and E2."""

from __future__ import annotations

import contextlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from sloth_soc.detectors.ensemble import EnsembleDetector
from sloth_soc.detectors.iforest import IsolationForestDetector
from sloth_soc.detectors.rf import RandomForestDetector
from sloth_soc.detectors.rules import RuleDetector
from sloth_soc.detectors.stat import StatDetector
from sloth_soc.evalkit.metrics import (
    cluster_bootstrap_ci,
    compute_binary_metrics,
    compute_per_scenario_recall,
    compute_precision_recall_at_k,
)
from sloth_soc.features import build_ip_day_features, features_to_dataframe
from sloth_soc.parsers import parse_file
from sloth_soc.synth.generator import SyntheticGenerator


def get_environment_info() -> dict[str, Any]:
    """Capture environment hardware, OS, and library versions for reproducibility."""
    try:
        git_sha = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"]).decode().strip()
    except Exception:
        git_sha = "unknown"

    pkgs = [
        "pydantic",
        "pandas",
        "scikit-learn",
        "scipy",
        "jinja2",
        "rich",
        "httpx",
    ]
    versions = {}
    for p in pkgs:
        with contextlib.suppress(Exception):
            versions[p] = importlib.metadata.version(p)

    return {
        "git_sha": git_sha,
        "hardware": {
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "cpu_cores": os.cpu_count() or 1,
        },
        "versions": versions,
    }


def build_split_dataframe(
    seeds: list[int],
    days: int = 7,
    shift: bool = False,
    temp_parent: Path | None = None,
) -> pd.DataFrame:
    """Generate synthetic logs for seeds, parse them, extract features, and join labels."""
    all_dfs = []
    base_dir = temp_parent or Path(tempfile.gettempdir())

    for seed in seeds:
        synth_out = base_dir / f"synth_seed_{seed}_{'shift' if shift else 'std'}"
        gen = SyntheticGenerator(seed=seed, days=days, shift=shift)
        gen.generate(synth_out)

        # Ingest events from the 4 sources
        events = []
        for src, rel_path in [
            ("sshd", "auth.log"),
            ("nginx", "nginx/access.log"),
            ("fail2ban", "fail2ban.log"),
            ("ufw", "ufw.log"),
        ]:
            file_p = synth_out / rel_path
            if file_p.exists():
                evs, _ = parse_file(file_p, source=src, year_hint=2026)  # type: ignore
                events.extend(evs)

        # Compute features
        feat_rows = build_ip_day_features(events)
        feat_df = features_to_dataframe(feat_rows)

        # Read ground truth labels
        labels_path = synth_out / "labels.csv"
        labels_df = pd.read_csv(labels_path)

        # Merge on (date, ip)
        labels_df = labels_df.rename(columns={"ip": "src_ip", "date": "day"})
        merged = pd.merge(feat_df, labels_df, on=["src_ip", "day"], how="inner")
        merged["label_binary"] = (merged["label"] == "malicious").astype(int)
        merged["date"] = merged["day"]
        all_dfs.append(merged)

        # Clean up disk space
        shutil.rmtree(synth_out, ignore_errors=True)

    if not all_dfs:
        return pd.DataFrame()

    return pd.concat(all_dfs, ignore_index=True)


def run_experiment_e1(
    train_seeds: list[int] | None = None,
    test_seeds: list[int] | None = None,
    out_dir: str | Path = "results",
) -> dict[str, Any]:
    """Experiment E1: Comprehensive detector comparison on held-out test seeds."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    tr_seeds = train_seeds or [1, 2, 3]
    te_seeds = test_seeds or [21, 22, 23, 24]

    train_df = build_split_dataframe(tr_seeds, days=7)
    test_df = build_split_dataframe(te_seeds, days=7)

    detectors = {
        "rules": RuleDetector(),
        "stat": StatDetector(),
        "iforest": IsolationForestDetector(seed=42),
        "rf_baseline": RandomForestDetector(seed=42),
        "ensemble": EnsembleDetector(seed=42),
    }

    # Fit detectors on train set
    for _name, det in detectors.items():
        det.fit(train_df, train_df["label_binary"])

    detector_results: dict[str, Any] = {}

    for name, det in detectors.items():
        scores = det.score(test_df)
        col_name = f"score_{name}"
        test_df[col_name] = scores

        bin_metrics = compute_binary_metrics(test_df["label_binary"].values, scores, threshold=0.5)
        p_at_k, r_at_k = compute_precision_recall_at_k(test_df, score_col=col_name, k=5)
        scenario_recall = compute_per_scenario_recall(test_df, score_col=col_name, threshold=0.5)

        # 95% bootstrap CI on F1
        f1_low, f1_high = cluster_bootstrap_ci(
            test_df,
            lambda df, sc=col_name: compute_binary_metrics(
                df["label_binary"].values, df[sc].values, threshold=0.5
            )["f1"],
            cluster_col="date",
            n_resamples=200,
        )

        detector_results[name] = {
            "metrics": {
                **bin_metrics,
                "precision_at_5": p_at_k,
                "recall_at_5": r_at_k,
                "f1_ci_95": [round(f1_low, 3), round(f1_high, 3)],
            },
            "per_scenario_recall": scenario_recall,
            "critical_scenario_recall_m4": scenario_recall.get("M4", 0.0),
        }

    env_info = get_environment_info()
    payload = {
        "experiment": "E1",
        "description": "Detector comparison on held-out test seeds",
        "created_at": datetime.now(UTC).isoformat(),
        **env_info,
        "n_train_days": len(train_df["date"].unique()),
        "n_test_days": len(test_df["date"].unique()),
        "n_test_rows": len(test_df),
        "detectors": detector_results,
    }

    with open(out_path / "E1.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return payload


def run_experiment_e1b(
    train_seeds: list[int] | None = None,
    shift_seeds: list[int] | None = None,
    out_dir: str | Path = "results",
) -> dict[str, Any]:
    """Experiment E1b: Generalization to distribution-shifted data without retraining."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    tr_seeds = train_seeds or [1, 2, 3]
    sh_seeds = shift_seeds or [101, 102, 103]

    train_df = build_split_dataframe(tr_seeds, days=7, shift=False)
    shift_df = build_split_dataframe(sh_seeds, days=7, shift=True)

    detectors = {
        "rules": RuleDetector(),
        "ensemble": EnsembleDetector(seed=42),
    }

    for _name, det in detectors.items():
        det.fit(train_df, train_df["label_binary"])

    results: dict[str, Any] = {}
    for name, det in detectors.items():
        scores = det.score(shift_df)
        shift_df[f"score_{name}"] = scores
        bin_metrics = compute_binary_metrics(shift_df["label_binary"].values, scores, threshold=0.5)
        scenario_recall = compute_per_scenario_recall(
            shift_df, score_col=f"score_{name}", threshold=0.5
        )
        results[name] = {
            "metrics": bin_metrics,
            "per_scenario_recall": scenario_recall,
            "critical_scenario_recall_m4": scenario_recall.get("M4", 0.0),
        }

    payload = {
        "experiment": "E1b",
        "description": "Generalization on distribution shift seeds without retraining",
        "created_at": datetime.now(UTC).isoformat(),
        **get_environment_info(),
        "detectors": results,
    }

    with open(out_path / "E1b.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return payload


def run_experiment_e2(
    train_seeds: list[int] | None = None,
    test_seeds: list[int] | None = None,
    out_dir: str | Path = "results",
) -> dict[str, Any]:
    """Experiment E2: Label efficiency curve (sample efficiency)."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    tr_seeds = train_seeds or [1, 2, 3]
    te_seeds = test_seeds or [21, 22]

    train_df = build_split_dataframe(tr_seeds, days=7)
    test_df = build_split_dataframe(te_seeds, days=7)

    # Flat reference: unsupervised IsolationForest (uses zero labels)
    iforest = IsolationForestDetector(seed=42)
    iforest.fit(train_df)
    iforest_scores = iforest.score(test_df)
    iforest_f1 = compute_binary_metrics(
        test_df["label_binary"].values, iforest_scores, threshold=0.5
    )["f1"]

    sample_sizes = [10, 20, 50, len(train_df)]
    curve: list[dict[str, Any]] = []

    for size in sample_sizes:
        actual_n = min(size, len(train_df))
        sub_train = train_df.sample(n=actual_n, random_state=42)

        rf = RandomForestDetector(seed=42)
        rf.fit(sub_train, sub_train["label_binary"])
        rf_scores = rf.score(test_df)
        rf_f1 = compute_binary_metrics(test_df["label_binary"].values, rf_scores, threshold=0.5)[
            "f1"
        ]

        curve.append(
            {
                "labeled_samples": actual_n,
                "rf_f1": round(rf_f1, 4),
                "iforest_reference_f1": round(iforest_f1, 4),
            }
        )

    payload = {
        "experiment": "E2",
        "description": "Label efficiency curve comparing supervised RF vs unsupervised IsolationForest",
        "created_at": datetime.now(UTC).isoformat(),
        **get_environment_info(),
        "curve": curve,
    }

    with open(out_path / "E2.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return payload
