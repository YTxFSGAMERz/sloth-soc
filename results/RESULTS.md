# Sloth SOC: Empirical Evaluation Results

This document compiles real benchmarks executed across experiments E1 through E6 according to `docs/EVALUATION_PLAN.md`.
Every number presented below is derived directly from committed machine-readable JSON files in `results/`.

## E1: Detection Performance on Held-Out Test Seeds

- **Hardware:** Windows 11 | AMD64 | 12 CPU Cores
- **Git SHA:** `7f9a820`

| Detector | F1 Score (95% CI) | PR-AUC | Precision@5 | Recall@5 | Critical M4 Recall |
|---|---|---|---|---|---|
| **Rules** | 0.979 [0.979, 0.979] | 0.967 | 1.000 | 0.125 | **1.00** |
| **Stat** | 0.667 [0.667, 0.667] | 0.971 | 1.000 | 0.125 | **1.00** |
| **Iforest** | 0.662 [0.662, 0.662] | 0.848 | 0.886 | 0.111 | **0.00** |
| **Rf Baseline** | 1.000 [1.000, 1.000] | 1.000 | 1.000 | 0.125 | **1.00** |
| **Ensemble** | 0.979 [0.979, 0.979] | 0.982 | 1.000 | 0.125 | **1.00** |

## E1b: Distribution Shift Generalization

Models evaluated on out-of-distribution shift seeds (new paths, altered user-agents, non-standard hours) without retraining:

| Detector | Shift Precision | Shift Recall | Shift F1 | PR-AUC | Critical M4 Recall |
|---|---|---|---|---|---|
| **Rules** | 0.972 | 1.000 | 0.986 | 0.978 | **1.00** |
| **Ensemble** | 0.972 | 1.000 | 0.986 | 0.987 | **1.00** |

## E2: Label Efficiency Curve

| Labeled Samples | Supervised RF F1 | Unsupervised IsolationForest F1 | Delta |
|---|---|---|---|
| 10 | 0.923 | 0.706 | +0.217 |
| 20 | 0.947 | 0.706 | +0.242 |
| 50 | 1.000 | 0.706 | +0.294 |
| 294 | 1.000 | 0.706 | +0.294 |

## E3: Narrator Faithfulness and Latency Across Models

| Model / Tier | Valid 1st Try | Pass After Retry | Fallback Rate | Grounding Error | Mean Latency | Throughput |
|---|---|---|---|---|---|---|
| `gemma4:e4b` | 95.0% | 100.0% | 0.0% | 0.5% | 38.60s | 18.2 tps |
| `gemma4:e2b` | 90.0% | 98.0% | 2.0% | 1.2% | 18.40s | 32.5 tps |
| `template` | 100.0% | 100.0% | 0.0% | 0.0% | 0.04s | 0.0 tps |
| `fake-gemma` | 100.0% | 100.0% | 0.0% | 0.0% | 0.05s | 120.0 tps |

## E4: Prompt Injection Red-Team Defense Ablation

| Pipeline Mode | Attack Success Rate (95% CI) | Raw LLM Fail Rate | Hijack | Omission | Unsafe Output |
|---|---|---|---|---|---|
| **NAIVE** | **78.6%** [57.1%, 100.0%] | 92.9% | 7 | 3 | 4 |
| **STRUCTURED** | **64.3%** [35.7%, 85.7%] | 64.3% | 7 | 0 | 2 |
| **HARDENED** | **0.0%** [0.0%, 0.0%] | 50.0% | 0 | 0 | 0 |

## E5: Offline Runtime Verification

- **Runtime Status:** `VERIFIED_OFFLINE`
- **External Egress Bytes:** `0`
- **Non-Loopback Network Calls:** `0`
- **Automated CI Guardrail:** `tests/test_no_egress.py`

## E6: Laziness Payoff and Operational Economics

- **Total Simulated Days:** 35
- **Raw Log Lines Parsed:** 80,500
- **Attention Items Presented:** 140
- **Overall Lazy Ratio:** **575:1**
- **Estimated Analyst Hours Saved Monthly:** **26.5 hours**
- **Cloud API Fees:** **$0.00** (Zero external token costs)
