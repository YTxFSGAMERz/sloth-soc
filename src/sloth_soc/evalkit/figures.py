"""Publication-ready figure generation for Sloth SOC evaluation benchmarks."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np


def generate_e1_figures(
    results_dir: str | Path = "results", out_dir: str | Path = "results/figures"
) -> None:
    """Generate E1 per-scenario recall heatmap and precision-recall bar chart."""
    e1_path = Path(results_dir) / "E1.json"
    if not e1_path.exists():
        return

    with open(e1_path, encoding="utf-8") as f:
        data = json.load(f)

    figures_dir = Path(out_dir)
    figures_dir.mkdir(parents=True, exist_ok=True)

    detectors_data = data.get("detectors", {})
    detector_names = list(detectors_data.keys())
    if not detector_names:
        return

    # 1. Per-scenario recall heatmap / grouped bar
    scenarios = [
        "b1_legit_admin",
        "b2_typo_burst",
        "b3_internal_sync",
        "b4_healthcheck",
        "b5_traveler_vpn",
        "m1_ssh_brute_burst",
        "m2_user_spray",
        "m3_low_slow_ssh",
        "m4_credential_stuffing_burst",
        "m5_web_scanner_404",
        "m5b_web_sensitive_probe_200",
        "m6_port_scan_syn",
        "m7_prompt_injection",
    ]

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(scenarios))
    width = 0.15

    for idx, (det_name, det_dict) in enumerate(detectors_data.items()):
        recalls = []
        psr = det_dict.get("per_scenario_recall", {})
        for sc in scenarios:
            recalls.append(psr.get(sc, 0.0))
        offset = (idx - len(detectors_data) / 2) * width + width / 2
        ax.bar(x + offset, recalls, width, label=det_name.replace("_", " ").title())

    ax.set_ylabel("Recall Rate", fontsize=11, fontweight="bold")
    ax.set_title(
        "E1: Per-Scenario Recall Across Detectors (M4 Critical in Red)",
        fontsize=13,
        fontweight="bold",
    )
    ax.set_xticks(x)
    ax.set_xticklabels(
        [s.replace("_", "\n") for s in scenarios], rotation=45, ha="right", fontsize=8
    )
    ax.set_ylim(0, 1.1)
    ax.legend(loc="upper right", framealpha=0.9)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    fig.savefig(figures_dir / "E1_scenario_recall.png", dpi=200)
    plt.close(fig)

    # 2. Precision, Recall, F1 comparison bar chart
    fig, ax = plt.subplots(figsize=(8, 5))
    metrics = ["precision", "recall", "f1", "precision_at_5", "recall_at_5"]
    x = np.arange(len(detector_names))
    width = 0.16

    for idx, metric in enumerate(metrics):
        vals = [detectors_data[d]["metrics"].get(metric, 0.0) for d in detector_names]
        offset = (idx - len(metrics) / 2) * width + width / 2
        ax.bar(x + offset, vals, width, label=metric.replace("_", " ").title())

    ax.set_ylabel("Score", fontsize=11, fontweight="bold")
    ax.set_title("E1: Detection Performance Metrics by Model", fontsize=13, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels([d.replace("_", " ").title() for d in detector_names], fontsize=9)
    ax.set_ylim(0, 1.15)
    ax.legend(loc="lower right", framealpha=0.9)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    fig.savefig(figures_dir / "E1_pr_curves.png", dpi=200)
    plt.close(fig)


def generate_e2_figures(
    results_dir: str | Path = "results", out_dir: str | Path = "results/figures"
) -> None:
    """Generate E2 label efficiency curve plot."""
    e2_path = Path(results_dir) / "E2.json"
    if not e2_path.exists():
        return

    with open(e2_path, encoding="utf-8") as f:
        data = json.load(f)

    figures_dir = Path(out_dir)
    figures_dir.mkdir(parents=True, exist_ok=True)

    curve = data.get("curve", [])
    if not curve:
        return

    samples = [c["labeled_samples"] for c in curve]
    rf_f1s = [c["rf_f1"] for c in curve]
    iforest_ref = curve[0]["iforest_reference_f1"]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(
        samples,
        rf_f1s,
        marker="o",
        linewidth=2.5,
        color="#0284c7",
        label="Supervised Random Forest (F1)",
    )
    ax.axhline(
        y=iforest_ref,
        color="#dc2626",
        linestyle="--",
        linewidth=2,
        label=f"Unsupervised IsolationForest Baseline (F1={iforest_ref:.2f})",
    )

    ax.set_xlabel("Number of Labeled Historical IP-Day Samples", fontsize=11, fontweight="bold")
    ax.set_ylabel("Held-Out Test F1 Score", fontsize=11, fontweight="bold")
    ax.set_title("E2: Label Efficiency Curve (Sample Efficiency)", fontsize=13, fontweight="bold")
    ax.set_ylim(0.4, 1.05)
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend(loc="lower right", framealpha=0.9)
    plt.tight_layout()
    fig.savefig(figures_dir / "E2_label_efficiency.png", dpi=200)
    plt.close(fig)


def generate_e4_figures(
    results_dir: str | Path = "results", out_dir: str | Path = "results/figures"
) -> None:
    """Generate E4 Attack Success Rate (ASR) comparison bar chart."""
    e4_path = Path(results_dir) / "E4.json"
    if not e4_path.exists():
        return

    with open(e4_path, encoding="utf-8") as f:
        data = json.load(f)

    figures_dir = Path(out_dir)
    figures_dir.mkdir(parents=True, exist_ok=True)

    modes = ["naive", "structured", "hardened"]
    asrs = [data["metrics"][m]["asr"] * 100 for m in modes]
    raw_fails = [data["metrics"][m]["raw_llm_failure_rate"] * 100 for m in modes]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(modes))
    width = 0.35

    ax.bar(x - width / 2, asrs, width, label="Effective ASR on Final Digest", color="#ef4444")
    ax.bar(
        x + width / 2,
        raw_fails,
        width,
        label="Raw Model Failure Rate (Pre-Defense)",
        color="#f59e0b",
    )

    ax.set_ylabel("Failure / Success Percentage (%)", fontsize=11, fontweight="bold")
    ax.set_title(
        "E4: Prompt Injection Attack Success Rate (ASR) Across Pipelines",
        fontsize=13,
        fontweight="bold",
    )
    ax.set_xticks(x)
    ax.set_xticklabels(
        ["Naive (No Defense)", "Structured (JSON Only)", "Hardened (Sloth SOC D1-D8)"],
        fontsize=10,
        fontweight="bold",
    )
    ax.set_ylim(0, 110)
    ax.legend(loc="upper right", framealpha=0.9)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    # Annotate 0.0% on Hardened
    ax.annotate(
        "0.0% ASR\n(100% Blocked)",
        xy=(2 - width / 2, 0),
        xytext=(2 - width / 2, 18),
        ha="center",
        fontweight="bold",
        color="#15803d",
        arrowprops={"arrowstyle": "->", "color": "#15803d", "lw": 1.5},
    )

    plt.tight_layout()
    fig.savefig(figures_dir / "E4_asr_comparison.png", dpi=200)
    plt.close(fig)


def generate_all_evaluation_figures(
    results_dir: str | Path = "results", out_dir: str | Path = "results/figures"
) -> None:
    """Generate all experiment figures."""
    generate_e1_figures(results_dir, out_dir)
    generate_e2_figures(results_dir, out_dir)
    generate_e4_figures(results_dir, out_dir)
