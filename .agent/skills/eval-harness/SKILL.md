---
name: eval-harness
description: Build the Sloth SOC synthetic-data generator, ground-truth labels, metrics, experiments E1 to E6, bootstrap confidence intervals, figures, and the auto-generated results table. Use this whenever you create or change synthetic logs, labels, seeds, distribution-shift data, metrics, benchmarks (latency, tokens per second, memory), the `sloth-soc eval` command, results files, figures, or any number that will appear in the README or the DEV post. Trigger on "evaluate", "benchmark", "precision recall", "test set", "synthetic data", "results", or "make a chart".
---

# Evaluation harness

Judges notice numbers, and they notice invented ones. Every number in the README and the post must come from a file in `results/` produced by a command anyone can rerun. This skill defines the data, the experiments, and the reporting rules.

## Synthetic generator (`synth/`; `sloth-soc synth --seed N --days 7 [--shift]`)

Output directory: `auth.log`, `nginx/access.log`, `fail2ban.log`, `ufw.log`, `labels.csv` (`date, ip, label, scenario, truth_severity`), `meta.json` (config, seed, versions, sha256 of each file).

Rules for realism and safety:

- Addresses: server `192.0.2.10`; clients and attackers from `198.51.100.0/24` and `203.0.113.0/24`; IPv6 from `2001:db8::/32`; internal `10.0.0.0/8`. Shuffle role assignment per seed so no detector can learn a role from an octet. Domains use `.invalid`.
- Background web traffic is a Poisson process with a diurnal rate. Brute force uses exponential inter-arrival times. fail2ban simulation bans after 5 failures in 10 minutes and unbans after the ban time.
- Deterministic: same seed gives byte-identical output (test it).
- The generator only writes text. It never sends network traffic. Optional lab traffic, if ever added, goes only to loopback or a Docker network created by the project.

| ID | Scenario | Label | Truth severity | Notes |
|---|---|---|---|---|
| B1 | Admin SSH logins by key from 1 or 2 known IPs in working hours | benign | info | |
| B2 | Known user, 1 to 4 typo failures then success | benign | info | must not trigger R5 |
| B3 | Customer web traffic, many IPs | benign | info | |
| B4 | Health-check monitor every 60 s; polite crawler with a few 404s | benign | info | low `iat_cv` on purpose |
| B5 | Admin logs in from a new IP (travel) | benign | low | R6 may fire; acceptable |
| B6 | Internal backup over SSH from RFC 1918 | benign | info | |
| M1 | SSH brute force on `root`, high rate, banned by fail2ban | malicious | medium | blocked |
| M2 | Username spray over several IPs | malicious | medium | |
| M3 | Low-and-slow SSH, 1 to 3 tries per hour for 24 hours, under the ban threshold | malicious | medium | hard for naive rules |
| M4 | Credential stuffing: >= 12 tries on a valid user, spaced under the ban threshold, then success | malicious | critical | must never be missed |
| M5 | Web probing of sensitive paths, 404s | malicious | medium | |
| M5b | As M5 but one probe path returns 200 | malicious | high | exposed file |
| M6 | Port scan: many distinct ports blocked by ufw | malicious | medium | |
| M7 | Injection-bearing attackers: payload text in username, user agent, or path (combined with M1 or M5) | malicious | medium | red team and R8 |

Hard cases are not optional: B2, B4, B5, M3 create the overlap that stops detectors scoring a meaningless 1.0.

Shift mode (`--shift`) changes probe-path list, user-agent strings, username dictionary, rates (slower attackers), and working hours. Splits: train seeds 1 to 10, test seeds 21 to 40, shift seeds 101 to 110.

## Metrics

Detection (IP-day level): precision, recall, F1, PR-AUC (average precision), precision@K and recall@K at the alert budget K = 5 per day, per-scenario recall. Critical recall is reported separately; one missed M4 is a failed run.
Narrator (digest level): first-try valid rate, validator pass rate after retries, fallback rate, grounding error rate (claims not in the brief), omission rate for severity >= high, status mismatch rate.
Injection: ASR and raw LLM failure rate (see `prompt-injection-defense`).
Performance: stage timings, end-to-end digest latency (cold and warm), tokens per second, approximate peak memory (state how it was measured), digest word count, lazy ratio (raw lines divided by items needing attention).
Uncertainty: cluster bootstrap over simulated days (resample days, not rows), 1,000 resamples, 95% intervals. Report n.

## Experiments (`sloth-soc eval --exp E1,E2,...` or `--all`)

- E1 Detector comparison: rules, stat, iforest, tabpfn (if available), rf baseline, ensemble. Output the per-scenario recall heatmap. E1b repeats on shift seeds to expose overfitting to our own generator.
- E2 Label efficiency: F1 or PR-AUC versus number of labeled training IP-days (10, 20, 50, 100, 500, all) for TabPFN, RF, logistic regression; iforest is a flat reference line because it uses no labels. Report honestly if TabPFN does not win.
- E3 Narrator quality and the "slow and steady" sweep: each available model (for example `gemma4:e2b`, `gemma4:e4b`, and a larger one if the hardware allows) over the same days; faithfulness metrics versus latency. State the hardware.
- E4 Injection ablation: naive, structured, hardened.
- E5 Offline proof: the whole demo passes with all non-loopback network calls forbidden (test) and a manual run with the network disabled (screenshot for the post).
- E6 Laziness and cost: lazy ratio, estimated minutes saved (state assumptions explicitly, for example "scanning one raw line per second versus reading the digest at 200 words per minute"), and cost: no per-token fees.

## Reporting rules

- Every run writes `results/<exp>.json` with `{experiment, created_at, git_sha, hardware, versions, config, n, metrics}` and PNG figures under `results/figures/`.
- `results/RESULTS.md` and the README results block are generated from those JSON files between `<!-- RESULTS:START -->` and `<!-- RESULTS:END -->` markers. Never hand-edit numbers there.
- Seed everything; record model digests (`ollama show`) and package versions.
- Include a "Threats to validity" section: synthetic data written by the same author as the rules, small scale, no adversary adapting to the defenses, one machine.
- If a result is bad, publish it with a diagnosis. It is better material for the post than a suspiciously perfect table.

## Pitfalls

Circular evaluation (generator and rules share assumptions: mitigate with shift seeds and independent hand-written fixtures); splitting by row; tuning on test seeds; comparing LLMs with different settings; reporting best-of-N runs; forgetting cold-start latency.
