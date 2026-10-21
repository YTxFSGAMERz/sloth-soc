# Sloth SOC: Evaluation Plan

Purpose: produce honest, reproducible evidence for four claims. (1) The tool finds what matters. (2) A local model narrates it faithfully. (3) Attacker-controlled log text cannot hijack the digest. (4) It works offline and saves real effort. Method details live in the `eval-harness` skill; this file fixes the protocol.

## 1. Datasets
| Split | Seeds | Config | Use |
|---|---|---|---|
| train | 1-10 | standard | tune thresholds, fit models |
| test | 21-40 | standard | all headline detection numbers |
| shift | 101-110 | `--shift` (new paths, user agents, rates, hours) | generalization (E1b) |
| lab (optional) | n/a | real logs from a system the author owns | sanity check, never in headline tables |

Each seed is a simulated week. Ground truth is `labels.csv` at (date, IP) level plus truth severity. Hard cases (B2, B4, B5, M3) must be present at meaningful rates. Generator output is byte-deterministic per seed.

## 2. Metrics
- **Detection:** precision, recall, F1, PR-AUC, precision@K and recall@K with K = 5 per day, per-scenario recall, critical recall (M4) reported on its own.
- **Narrator:** first-try valid rate, pass rate after retries, fallback rate, grounding error rate, omission rate for severity >= high, status mismatch rate.
- **Injection:** attack success rate (ASR) on the final digest, raw LLM failure rate, fallback rate, breakdown by family and field.
- **Performance:** stage timings, digest latency cold and warm, tokens per second, approximate peak memory (state method), digest word count.
- **Laziness:** lazy ratio = raw lines / items needing attention; estimated minutes saved with stated assumptions.
- **Uncertainty:** cluster bootstrap over simulated days, 1,000 resamples, 95% intervals, with n reported.

## 3. Experiments
| ID | Question | Protocol | Output |
|---|---|---|---|
| E1 | Which detector finds what? | Fit on train, evaluate on test: rules, stat, iforest, tabpfn (if available), rf baseline, ensemble | `E1.json`, per-scenario recall heatmap, PR curves |
| E1b | Does it generalize beyond our own generator? | Same models on shift seeds without retuning | `E1b.json`, delta table |
| E2 | What do labels buy? | Train sizes 10, 20, 50, 100, 500, all; TabPFN vs RF vs logistic regression; iforest as flat reference | `E2.json`, label-efficiency curve |
| E3 | Does a bigger, slower model narrate better? | Same 20 simulated days across installed Gemma sizes (e.g. `gemma4:e2b`, `gemma4:e4b`, larger if hardware allows); temperature 0, fixed seed | `E3.json`, latency vs faithfulness plot, hardware table |
| E4 | Which defense layer matters? | `naive`, `structured`, `hardened` on the red-team suite; optional ablations (no validator, untrusted text included) | `E4.json`, ASR bars, family breakdown |
| E5 | Is it really offline? | No-egress test in CI plus a manual network-off run | test log, screenshot |
| E6 | How lazy is the payoff? | Lazy ratio, digest word count, assumptions stated; cost = no per-token fees | `E6.json`, summary table |

## 4. Protocol rules
1. Tune on train seeds only; freeze thresholds before touching test seeds.
2. If every detector exceeds 0.99, harden the generator (more overlap) and rerun everything; do not report a trivially perfect table.
3. Use identical LLM settings across models (temperature, seed, `num_ctx`, `think`), and record model digests.
4. Run each LLM experiment cold once and warm for the measured runs.
5. Never discard a failing case; list it with a diagnosis.
6. Report n, intervals, hardware (CPU, RAM, GPU if any, OS), library versions, and the git SHA in every results file.
7. Anything that appears in prose must be traceable to a results file.

## 5. Reporting format
`results/<exp>.json`: `{experiment, created_at, git_sha, hardware, versions, config, n, metrics}`. `results/figures/*.png`. `results/RESULTS.md` is generated. The README block between `<!-- RESULTS:START -->` and `<!-- RESULTS:END -->` is generated. A "Threats to validity" section is mandatory.

## 6. Threats to validity (write these down)
- Rules and generator come from one author, so rule recall is optimistic. Shift seeds and independent hand-written parser fixtures reduce, not remove, this.
- Synthetic traffic lacks the weirdness of the real internet. The optional lab check is a sanity test, not proof.
- Small scale: one machine, a few models, a bounded payload suite.
- No adaptive adversary who iterates against the defenses.
- LLM nondeterminism across versions, quantizations, and hardware.

## 7. Targets (aims, not promises; report actuals)
Critical scenario recall of 100% on test seeds; recall@5 of at least 0.9 at precision@5 of at least 0.8; grounding error rate below 2% after validation; hardened ASR of 0 on the suite with the raw model failure rate reported next to it; digest latency under 90 s on the author's laptop with a small model.
