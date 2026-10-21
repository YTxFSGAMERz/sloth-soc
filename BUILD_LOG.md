# Sloth SOC: Build Log (Append-Only Journal)

This journal records build actions, commands run, output highlights, failures encountered, fixes applied, and performance metrics across development phases. It serves as raw, authentic material for the final DEV article.

---

## [2026-10-21] Phase 0: Foundations & Project Kickoff

### Goal
Establish project foundations: repository scaffold, MIT license, data contracts (`schema.py`), configuration with loopback guardrail (`config.py`), sanitization with injection heuristics (`sanitize.py`), initial CLI with health diagnostics (`doctor`), and test suite.

### Actions & Commands
1. **Kit Migration**: Relocated kit files according to manifest in `00_START_HERE.md` to `.agent/rules/`, `.agent/skills/`, `.agent/workflows/`, and `docs/`. Verified all 18 files placed correctly.
2. **Environment & Scaffold**:
   - Initialized Git repository (`git init`).
   - Configured `pyproject.toml` with Python 3.11+ requirement, dependencies (Typer, Pydantic v2, PyYAML, Pandas, Scikit-learn, Scipy, Jinja2, Rich, HTTPX), dev tools (Pytest, Hypothesis, Ruff), and CLI entry point `sloth-soc = sloth_soc.cli:app`.
   - Created `LICENSE` (MIT) and `.gitignore`.
   - Created GitHub Actions CI workflow `.github/workflows/ci.yml`.
3. **Data Contracts (`src/sloth_soc/schema.py`)**:
   - Defined `Event`, `RawRef`, `Unparsed`, `ParseStats`, `FeatureRow`, `Finding`, `Brief`, `NarratorOutput`, `DigestItem`, `DigestMeta`.
   - Added `to_ml_dict()` method on `FeatureRow` ensuring zero data leakage of IP, date, scenario labels, or truth values into ML models.
   - Frozen after Phase 0.
4. **Configuration & Safety Guard (`src/sloth_soc/config.py`)**:
   - Created typed settings for host, timezone, sources, detection thresholds, LLM connection, and output options.
   - Enforced loopback-only validation for LLM endpoint (`127.0.0.1`, `localhost`, `::1`) unless `allow_remote: true` is explicitly provided.
   - Provided `config.example.yaml`.
5. **Sanitization (`src/sloth_soc/sanitize.py`)**:
   - Built `clean_field` to strip ANSI escape sequences, C0/C1 control codes (including `\r` and `\n` to prevent log forging), Unicode bidi overrides, and zero-width spaces.
   - Enforced field length caps (user: 64, host: 64, path: 160, ua: 120, default: 256).
   - Built `detect_injection_markers` for Rule R8 to flag prompt injection attempts.
6. **Diagnostics CLI (`sloth_soc/cli.py`)**:
   - Implemented `sloth-soc doctor` command checking Python version, dependencies, Ollama reachability, model availability, TabPFN status, and network state.
   - Stubs provided for `demo`, `synth`, `run`, `eval`, `redteam`.
7. **Tests**:
   - `tests/test_sanitize.py`: ANSI, CRLF log forging, bidi, zero-width, length caps, idempotency, injection markers.
   - `tests/test_schema.py`: Event deterministic ID, ParseStats coverage, feature leakage prevention, brief & finding creation, narrator output schema.
   - `tests/test_config.py`: defaults, loopback host validation, YAML loader.
   - `tests/test_doctor.py`: CLI invocation of `doctor`.

### Failures & Fixes
- *Issue*: Ollama Windows client returned `Unable to init instance: Unspecified error` when run non-interactively in CLI background task.
- *Fix*: In non-interactive developer environments, Ollama background service must be launched via desktop app or `ollama serve`. In the meantime, code and tests gracefully handle unreachable Ollama by using `FakeLLM` and `--no-llm` fallback, exactly as planned in `docs/SPEC.md` and `docs/BUILD_PLAN.md`.

### Status & Next Steps
- Phase 0 foundation complete. All unit tests passed, repo committed.
- Proceeding to Phase 1 (Data Engine).

---

## [2026-10-21] Phase 1: Data Engine (Synthetic Generator & Log Parsers)

### Goal
Build the synthetic log generator supporting scenarios B1-B6, M1-M7, and M5b with ground-truth labels and byte-determinism, and implement the four robust log parsers (`sshd`, `nginx`, `fail2ban`, `ufw`) with parse statistics and fuzz/round-trip tests.

### Actions & Commands
1. **Parsers (`src/sloth_soc/parsers/`)**:
   - `base.py`: `ParserContext`, `validate_ip` (handles IPv4/IPv6, strips scopes), `parse_timestamp` (syslog & ISO-8601 with 7-day future rollover protection).
   - `sshd.py`: OpenSSH syslog & ISO parser with support for `auth_fail`, `auth_ok`, `invalid_user`, `disconnect`, `max_attempts`, and PAM failures. Sanitizes free text.
   - `nginx.py`: Combined Log Format parser handling custom formats, malformed HTTP requests, TLS binary probes, status codes, and bytes.
   - `fail2ban.py`: Parses `Ban`, `Restore Ban`, `Unban`, and `Found` actions with jail names.
   - `ufw.py`: Kernel netfilter log parser extracting `SRC`, `DST`, `PROTO`, `SPT`, `DPT`.
   - `__init__.py`: Registry with `get_parser`, `parse_stream`, and `parse_file` supporting compressed `.gz` and rotated logs.
2. **Synthetic Generator (`src/sloth_soc/synth/`)**:
   - `constants.py`: Reserved IP pools (RFC 5737 TEST-NET-1/2/3, RFC 3849 IPv6, RFC 1918 backup), probe path lists, and prompt injection test payloads.
   - `generator.py`: Generates `auth.log`, `nginx/access.log`, `fail2ban.log`, `ufw.log`, `labels.csv`, and `meta.json`. Shuffles IP roles per seed to prevent shortcut learning.
   - Added `sloth-soc synth` CLI command.
3. **Tests**:
   - `tests/test_parsers_golden.py`: 6 hand-crafted lines per parser, including hostile ANSI escapes, CRLF log forging, and IPv6.
   - `tests/test_parsers_fuzz.py`: Property-based fuzz tests with `hypothesis` (`st.text()`) ensuring zero exceptions.
   - `tests/test_synth_determinism.py`: Byte-determinism verification across runs and RFC-reserved IP safety check.
   - `tests/test_synth_roundtrip.py`: Synthetic dataset round-trip coverage asserting >= 99% parse coverage across all sources.

### Failures & Fixes
- *Issue*: A golden test line with an embedded newline failed because `SSHD_PREFIX_RE.match` did not match across `\n`.
- *Fix*: Hardened all parsers to strip `\r` and `\n` at the start of `parse_line`, completely neutralizing CRLF log forging injection before regex matching.

### Status & Next Steps
- 29/29 tests passing.
- `ruff check` and `ruff format` 100% clean.
- Phase 1 committed.

---

## [2026-10-21] Phase 2: Detection Layer & Evaluation Benchmarks

### Goal
Implement baseline state tracking, multi-scale IP-day feature engineering, deterministic rules R1-R8, Poisson/FDR stat detector, IsolationForest, RF baseline, ensemble detector, findings with attention budgeting and handled grouping, and initial evaluation benchmarks (E1, E1b, E2).

### Actions & Commands
1. **Baseline State (`src/sloth_soc/state.py`)**:
   - Built `StateStore` with SQLite persistence for `known_ips`, `known_user_ips`, and `hourly_baselines`.
   - Strictly enforces baseline isolation: baselines are only updated from previous historical days.
2. **Feature Engineering (`src/sloth_soc/features.py`)**:
   - Built `build_ip_day_features`: computes 5-minute sliding window burst max, Shannon entropies for usernames/paths, inter-arrival time coefficient of variation (`iat_cv`), sensitive web probing counts, firewall drops, and injection marker hit counts.
   - Verified zero leakage of IP, date, scenario labels, or ground truth into ML features via `test_features.py`.
3. **Detectors (`src/sloth_soc/detectors/`)**:
   - `rules.py`: Rules R1 through R8 covering brute-force burst, user spray, sensitive path probing, port scans, critical credential stuffing, new location logins, low-and-slow probing, and prompt injection attempts.
   - `stat.py`: Poisson tail probability tests with Benjamini-Hochberg FDR control ($q=0.05$).
   - `iforest.py`: Unsupervised IsolationForest with robust scaling and percentile ranking.
   - `rf.py`: Supervised Random Forest tabular classifier benchmark.
   - `tabpfn_det.py`: Optional TabPFN classifier with lazy import and graceful fallback.
   - `ensemble.py`: Rank-averaging ensemble blending rule severity floors with statistical/ML rankings.
4. **Findings & Attention Budget (`src/sloth_soc/findings.py`)**:
   - Generates `Finding` contracts with structured evidence and safe `ActionEnum` values.
   - Partitions into "Needs attention" (capped at budget=5, Critical prioritized) and "Handled while you slept" (blocked items at severity <= medium).
   - Assigns deterministic status: `urgent` on critical, `attention` on high/medium, `quiet` otherwise.
5. **Evaluation Harness (`src/sloth_soc/evalkit/`)**:
   - Implemented `sloth-soc eval --exp E1,E1b,E2`:
     - `E1`: Detector comparison on test seeds (seeds 21-24) after fitting on train seeds (1-3).
     - `E1b`: Generalization test on distribution shift seeds (101-103) without retraining.
     - `E2`: Label efficiency curve comparing sample sizes (10, 20, 50, full).
   - Generates machine-readable `results/E1.json`, `results/E1b.json`, `results/E2.json` with hardware, versions, and 95% bootstrap confidence intervals.
6. **Tests**:
   - `tests/test_state.py`: SQLite baseline integrity and known user/IP tracking.
   - `tests/test_features.py`: Multi-scale feature extraction and strict feature leakage assertions.
   - `tests/test_detectors.py`: Rules R1-R8, stat FDR, IsolationForest, and Ensemble rank-averaging.
   - `tests/test_findings.py`: Budget truncation, handled grouping, and deterministic status.

### Failures & Fixes
- *Issue*: Sparse DataFrames in tests caused `row.get("auth_fail_max_5m")` to return `NaN`, raising `ValueError: cannot convert float NaN to integer`.
- *Fix*: Created robust `_safe_int` and `_safe_float` coercion helpers that gracefully map `None` or `NaN` to clean numerical defaults.

### Metrics Snapshot (from `results/E1.json`)
- **Ensemble F1**: `0.979` (95% CI: `[0.976, 0.982]`)
- **Ensemble PR-AUC**: `0.982`
- **Precision@5**: `1.000` (exceeds target >= 0.80)
- **Critical M4 Scenario Recall**: `1.00` (100% - hits target 100%)
- **IsolationForest M4 Recall**: `0.00` (proves why unsupervised ML alone fails on low-and-slow stuffing and validates the hybrid architecture ADR-4).

### Status & Next Steps
- 46/46 tests passing.
- `ruff check` and `ruff format` 100% clean.
- Phase 2 complete. Ready for commit.
- Next: Phase 3 (Narrator, Security, and Demo: Ollama client with loopback guard, JSON-schema output, grounding validator V1-V7, template fallback, renderers, red-team injection suite, and `sloth-soc demo`).


