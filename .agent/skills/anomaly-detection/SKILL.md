---
name: anomaly-detection
description: Build and tune the Sloth SOC detection layer: per-IP-per-day feature engineering, deterministic rules, Poisson/FDR statistics, IsolationForest, optional TabPFN classification, ensemble scoring, severity mapping, and per-finding explanations. Use this whenever you add or change a feature or detector, pick thresholds, split train/test data, compare detectors, explain why an IP was flagged, or integrate TabPFN. Trigger on "anomaly", "score events", "detect brute force", "false positives", "alert budget", "Isolation Forest", or "TabPFN".
---

# Detection layer

Goal: out of thousands of log lines, surface the few things a human should read, with a reason for each. The LLM never decides what is dangerous; this layer does, deterministically and reproducibly.

## Unit of analysis

One row per `(src_ip, utc_day)`, the "IP-day". Multi-scale features (5-minute, hourly, daily) live inside that row, so low-and-slow scanners (a few tries per hour, all day) and fast bursts are both visible. The evaluation label is the generator's ground truth for that IP-day (see the `eval-harness` skill).

Never feed ML-only detectors the IP itself, scenario names, labels, or rule outputs. Otherwise the benchmark measures leakage, not detection. Add a unit test that asserts the feature columns exclude these.

## Features (`features.py`; log1p plus robust scaling for ML, raw values kept for explanations)

| Group | Feature | Definition |
|---|---|---|
| auth | `auth_fail_total`, `auth_fail_max_5m` | failures per day; maximum in any 5-minute sliding window |
| auth | `distinct_users`, `invalid_user_ratio` | usernames tried; share that do not exist |
| auth | `user_entropy` | Shannon entropy (bits) of attempted usernames |
| auth | `auth_ok_total`, `ok_after_fail` | successes; 1 if a success follows >= 10 failures within 30 minutes |
| timing | `iat_cv`, `active_hours` | std/mean of inter-arrival times (bots are regular); hours with any activity |
| web | `http_total`, `http_4xx_ratio`, `http_404_ratio` | volume and error shape |
| web | `probe_hits`, `probe_2xx` | hits on a curated probe-path list (`/.env`, `/.git/config`, `/wp-login.php`, `/phpmyadmin`, `/admin`, `/xmlrpc.php`, ...); probe paths that returned 2xx |
| web | `distinct_paths`, `path_entropy`, `ua_suspicious`, `ua_distinct` | scanning breadth; empty or generic tool user agents |
| fw | `fw_block_total`, `distinct_dst_ports`, `max_ports_5m` | firewall drops and port diversity |
| context | `banned`, `sources_touched`, `first_seen_ever`, `new_source_for_user` | fail2ban bans; how many log sources saw the IP; baseline novelty |
| safety | `inj_marker_hits` | instruction-like or markup-like text in untrusted fields (rule R8) |

## Detectors (`detectors/`; one protocol: `fit(X, y=None)`, `score(X) -> [0,1]`, `explain(row)`)

1. `rules` (deterministic; thresholds live in config and are tuned on train seeds only):
   - R1 brute-force burst: `auth_fail_max_5m >= 10`
   - R2 user spray: `distinct_users >= 8` and `invalid_user_ratio >= 0.6`
   - R3 web probing: `probe_hits >= 5`; R3b a probe path served 2xx (severity high)
   - R4 port scan: `max_ports_5m >= 15`
   - R5 success after failures from an unknown source (severity critical)
   - R6 known user from a new source (severity low)
   - R7 low-and-slow: `auth_fail_total >= 8`, `active_hours >= 6`, no burst
   - R8 injection attempt in untrusted fields (severity medium)
2. `stat`: Poisson tail probability of the observed 5-minute failure and 404 counts against a per-hour baseline rate (`scipy.stats.poisson.sf(k - 1, lam)`, with `lam` floored at a small epsilon). Adjust p-values with Benjamini-Hochberg at q = 0.05 so thousands of IP-days do not produce thousands of false alarms. Score = clipped `-log10(p_adj)`.
3. `iforest`: `IsolationForest(n_estimators=300, random_state=seed)` on scaled features, fit on baseline days. `score_samples` is higher for normal points, so negate it and convert to a percentile rank.
4. `tabpfn` (optional): supervised classifier on the same features.
   - Read the current docs before coding (docs.priorlabs.ai quickstart and "Selecting model version"); names and checkpoints change between releases, so do not code the API from memory.
   - Lazy import. Cap training rows (about 5,000 on CPU) or use the Fast checkpoint if it is slow.
   - First use needs an online login, license acceptance, and a weight download. Afterwards set `TABPFN_MODEL_CACHE_DIR` and confirm it works offline.
   - If import, license, or weights fail, report `unavailable` and continue. The digest footer lists which detectors ran.
5. `rf` (evaluation only): `RandomForestClassifier` baseline so TabPFN is judged against something honest.
6. `ensemble`: rank-average of `stat`, `iforest`, and `tabpfn` when present. Severity comes from rules first. ML may raise `low` to `medium` but never lowers a rule-assigned severity, and any critical rule always reaches the digest.

## Findings and the attention budget

Convert ranked IP-days into `Finding` objects (`schema.py`): `id (F1, F2, ...), severity, kind, entity, window, evidence (counts, first/last ts, blocked flags), reasons (rule codes plus top features), evidence_refs (at most 20 raw_refs), score`.

The digest shows at most `attention_budget` (default 5) findings that need a human. Anything blocked and at most medium is summarised under "handled". Explain ML hits with robust z-scores against the baseline (median and MAD), for example `auth_fail_max_5m = 38 (baseline median 0)`.

## Method discipline

- Split by seed (whole simulated weeks), never by row. Tune on train seeds, report on test seeds and on the distribution-shifted set (E1b).
- Report per-scenario recall, not only an aggregate; the detector-by-scenario heatmap is the interesting figure.
- Compare detectors at the same alert budget (precision@K, recall@K) as well as PR-AUC.
- If every detector scores above 0.99 the data is too easy. Add overlap (regular-interval health checks, crawlers with 404s, admins with typo storms) before trusting any number.
- Fix random seeds and log library versions.

## Pitfalls

Thresholds tuned on the test set; features that contain the label; a high PR-AUC that only reflects class imbalance (also report precision@K); TabPFN timing on CPU not measured; flagging a benign health-check because its `iat_cv` is low.
