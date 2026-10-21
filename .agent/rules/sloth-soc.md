# Sloth SOC: always-on rules

These apply to every task in this workspace. They exist because the project's value is trust: an offline, defensive tool whose numbers are real. When a rule seems to conflict with a task, stop and record the conflict in `DECISIONS.md` rather than quietly bending it.

## 1. Privacy and network
- Runtime is offline. The only permitted network traffic is loopback (127.0.0.0/8, ::1) to the local LLM server. Setup-time downloads (package installs, `ollama pull`, first TabPFN weight fetch) are fine, but nothing at run time.
- No telemetry, analytics, crash reporters, or remote logging in the shipped tool. Dev-time tracing may be added only with synthetic data and must be optional.
- A test must fail if the pipeline attempts any non-loopback connection or DNS lookup. Keep it green.
- The LLM client refuses non-loopback hosts unless `llm.allow_remote` is explicitly true.

## 2. Defensive scope and ethics
- Defensive tool only: detect, explain, harden. Do not write exploits, malware, credential attackers, scanners, or anything that sends hostile traffic.
- Default data is synthetic. Use RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and RFC 3849 (2001:db8::/32) addresses and `.invalid` domains. Never commit real IPs, hostnames, usernames, or logs.
- The red-team suite only feeds inert strings into our own pipeline. No live exfiltration endpoints.
- Real-log mode is for systems the user owns or is authorised to monitor.

## 3. Untrusted input
- Every field parsed from a log is attacker-controlled. Sanitize at parse time, never interpolate into shell commands, paths, SQL, HTML, or prompts without the documented defenses (`prompt-injection-defense` skill).
- The LLM never decides severity, status, entities, or actions. It narrates structured findings and its output is validated.
- Render with autoescaping and a locked-down CSP; strip control characters before terminal output.

## 4. Honesty
- Every number in the README, docs, or post must come from a file in `results/` that a command you ran produced. Never invent, round up, or "estimate" a result. If you could not run something, say so.
- Label synthetic results as synthetic. Keep failing cases visible. Do not tune test data or thresholds on the test split.
- Do not claim the system is secure, immune, or complete. Say what was tested and what residual risk remains.

## 5. Engineering standards
- Python 3.11+, type hints, pydantic v2 for contracts, `pathlib` for paths, cross-platform commands (the developer may be on Windows).
- `ruff check`, `ruff format`, and `pytest -q` must pass before every commit. New behavior needs tests; bug fixes need a regression test.
- Deterministic by default: fixed seeds, temperature 0 for the LLM, stable ids.
- Small conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`). First commit happens in Phase 0.
- Keep dependencies few and OSS-licensed; pin versions in `pyproject.toml`; record licenses and model terms in `docs/LICENSES.md`, verified against each official page rather than assumed.
- No secrets in the repo. Tokens come from environment variables; `.env` is git-ignored.
- Comments explain why, not what. Prefer boring, readable code.

## 6. Working style
- Plan first: Task List and Implementation Plan before code, Walkthrough with evidence after.
- Append to `BUILD_LOG.md` after each phase: what was built, commands and key output, failures and fixes, metrics snapshot. This is the raw material for the post.
- Decide rather than ask. Ask only when blocked by a human-only step, a security-relevant ambiguity, or a change to the scope in `docs/SPEC.md`.
- Verify before claiming: run the command, read the real output.
- When docs or skills disagree with reality (a model tag, an API, a flag), trust reality, check the official source, fix the docs, and log it in `DECISIONS.md`.
- No new features after the Phase 4 freeze. Polish, evidence, and writing only.
