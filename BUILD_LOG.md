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
- Phase 0 foundation complete. All unit tests ready for execution.
- Next: run `ruff` and `pytest`, verify `sloth-soc doctor`, commit Phase 0, then proceed to Phase 1 (Data Engine).
