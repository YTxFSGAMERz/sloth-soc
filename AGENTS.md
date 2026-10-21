# AGENTS.md: Sloth SOC

An offline "lazy security analyst". It parses server logs (sshd, nginx, fail2ban, ufw), finds what matters with rules, statistics, and ML, and has a local open-weight LLM (Gemma via Ollama) write a short morning digest. Principle: **math decides, the LLM only narrates.** Built for the Hacktoberfest Open-Source AI Challenge: Week 3 ("Slow and Steady") on DEV.

## Read first
1. `docs/SPEC.md` (what), `docs/ARCHITECTURE.md` (how), `docs/THREAT_MODEL.md` (what can go wrong), `docs/EVALUATION_PLAN.md` (how we prove it), `docs/BUILD_PLAN.md` (order of work).
2. `.agent/rules/sloth-soc.md` (always-on guardrails).
3. Skills in `.agent/skills/`: `log-parsing`, `anomaly-detection`, `local-llm-digest`, `prompt-injection-defense`, `eval-harness`, `devto-post-writer`. Open the matching one before working in its area.
4. Workflows: `/phase N`, `/run-evals`, `/ship-it`.

## Commands (keep this list accurate as the code evolves)
```bash
uv sync --all-extras          # or: python -m venv .venv && pip install -e ".[dev,eval]"
sloth-soc doctor              # versions, Ollama on loopback, model present, TabPFN availability
sloth-soc demo                # synthetic week -> digest (md, html, json)
sloth-soc demo --no-llm       # same, deterministic template narration
sloth-soc synth --seed 1 --days 7 [--shift]
sloth-soc run --config config.yaml [--date YYYY-MM-DD] [--no-llm]
sloth-soc eval --all          # experiments E1-E6 -> results/
sloth-soc redteam [--quick]   # naive vs structured vs hardened
pytest -q && ruff check . && ruff format --check .
```

## Layout
```
src/sloth_soc/  cli.py config.py schema.py sanitize.py state.py features.py findings.py
                parsers/ detectors/ llm/ render/ synth/ evalkit/ redteam/
tests/          unit/ property/ integration/ security/
docs/  results/  digests/  examples/  deploy/  .agent/{rules,skills,workflows}
BUILD_LOG.md (append-only journal)   DECISIONS.md (deviations and why)
```

## Conventions
- Python 3.11+, typed, pydantic v2 contracts in `schema.py` (frozen after Phase 0; changes need a `DECISIONS.md` entry).
- Deterministic by default: seeds, temperature 0, stable ids.
- CI-safe: unit and integration tests use `FakeLLM`; no model downloads in CI.
- Cross-platform commands; `pathlib`; no bash-only scripts without an equivalent.

## Definition of done for any change
Tests added or updated, `ruff` and `pytest` green, docs updated if behavior changed, `BUILD_LOG.md` entry for anything non-trivial, and no number published that lacks a file in `results/`.

## Hard boundaries
Offline at runtime (loopback LLM only), defensive scope only, synthetic data by default, all log text treated as hostile input. Details in `.agent/rules/sloth-soc.md`.
