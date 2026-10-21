# Sloth SOC: Build Plan

Deadline: **Sunday Oct 25, 2026, 11:59 PM PDT** (06:59 UTC on Oct 26). Day 1 is Wednesday Oct 21. Convert the deadline to your local time and aim to publish at least several hours early. Writing quality weighs most, so the plan protects time for the post.

| Day | Date | Phases | Goal |
|---|---|---|---|
| 1 | Wed Oct 21 | P0, P1 | Scaffold, contracts, synthetic data, parsers |
| 2 | Thu Oct 22 | P2 | Detection and first results |
| 3 | Fri Oct 23 | P3 | Narrator, validator, renderers, red team, working demo |
| 4 | Sat Oct 24 | P4 | Hardening, experiments, figures, README, **feature freeze at the end of the day** |
| 5 | Sun Oct 25 | P5 | Write, record, verify, publish with margin |

If ahead, pull work forward. If behind, apply the cut-lines at the bottom rather than compressing the writing day.

## P0 Foundations (about 1.5 h)
Tasks: repo scaffold (`pyproject.toml`, src layout, `uv` or venv), LICENSE (MIT), `.gitignore`, ruff and pytest config, GitHub Actions CI (tests with `FakeLLM`, no model downloads), `schema.py`, `config.py`, `sanitize.py` with tests, CLI skeleton with `doctor`, `BUILD_LOG.md`, `DECISIONS.md`, first commit.
Skills: `prompt-injection-defense` (sanitizer), `local-llm-digest` (config).
Exit: `pytest -q` and `ruff check .` green; `sloth-soc doctor` prints versions, Ollama reachability, model presence, TabPFN availability, and network status; `schema.py` frozen (later changes need a `DECISIONS.md` entry).

## P1 Data engine (about 4 h)
Tasks: synthetic generator (scenarios B1-B6, M1-M7, M5b; labels; `meta.json`; shift mode; determinism), four parsers, `ParseStats`, golden and fuzz and round-trip tests, `sloth-soc synth`.
Skills: `eval-harness`, `log-parsing`.
Exit: `sloth-soc synth --seed 1 --days 7` writes logs and labels; same seed yields identical sha256; parse coverage at least 99% on synthetic logs; fuzz tests green; IPs only from reserved ranges.

## P2 Detection (about 7 h)
Tasks: `state.py` baselines, `features.py`, rules R1-R8, `stat`, `iforest`, `rf` baseline, `ensemble`, `findings.py` with attention budget and "handled" grouping, optional `tabpfn` (skip gracefully if blocked), E1, E1b, initial E2.
Skills: `anomaly-detection`, `eval-harness`.
Exit: `sloth-soc eval --exp E1` writes `results/E1.json` with per-scenario recall and intervals; critical recall is 100% on test seeds or the gap is diagnosed; a unit test proves no label or scenario columns reach ML features; results are not trivially perfect (else harden the generator); thresholds frozen after tuning on train seeds.

## P3 Narrator, security, demo (about 7 h)
Tasks: Ollama client with loopback guard, prompt and schema, validator V1-V7, template fallback, `FakeLLM`, renderers (Markdown, HTML with CSP, terminal, JSON), red-team suite (nine families, three modes), `sloth-soc demo` end to end, first E3 and E4 runs.
Skills: `local-llm-digest`, `prompt-injection-defense`.
Exit: `sloth-soc demo` and `demo --no-llm` both succeed; validator tests cover valid, malformed, wrong status, hallucinated IP, URL, copied canary, missing critical finding; `sloth-soc redteam --quick` prints the ASR table; HTML test confirms CSP and no external URLs; digest screenshot captured with the browser tool.

## P4 Hardening, evidence, polish (about 7 h)
Tasks: no-egress test, model-size sweep (E3), E5, E6, figures, README with generated results block and screenshots, scheduling examples (cron, systemd timer, Task Scheduler), committed sample digests under `examples/`, `docs/LICENSES.md`, CI green, clean-clone test, start `docs/POST_DRAFT.md`.
Skills: `eval-harness`, `devto-post-writer`.
Exit: `/ship-it` dry run passes everything except the final human edit. **Feature freeze:** after this phase, only fixes, evidence, and writing.

## P5 Write and ship (Day 5)
Tasks: edit the post in the author's own voice, record the 60 to 90 second demo, final numbers audit, partner steps (see `docs/SUBMISSION_CHECKLIST.md`), publish, tag `v0.1.0`.
Skills: `devto-post-writer`.
Exit: post live with the challenge template and tags; repo public with working quickstart; links verified in a private window.

## Optional parallelism (only after P0 freezes `schema.py`)
Agent A owns `parsers/`, `synth/`, `features.py`, `detectors/`, `findings.py`. Agent B owns `llm/`, `render/`, `redteam/`. Shared files (`schema.py`, `cli.py`, `docs/`) change only in the main branch via small pull requests. Use separate branches and merge at the end of P2 and P3.

## Cut-lines (apply in this order if behind)
1. Drop TabPFN; keep IsolationForest. Explain why in the post.
2. Reduce E3 to two models and the red-team suite to `--quick` sizes.
3. Drop the `ufw` parser and scenario M6.
4. Drop E2.
5. Never drop: synthetic generator with labels, rules plus iforest, narrator plus validator, hardened versus naive red-team, README with real numbers, the post.

## Stretch backlog (after the freeze criteria are met, never before)
`ask` command; Tinker fine-tune on synthetic data; offline GeoIP; `.tech` project page; Temporal-wrapped nightly job; Sentry tracing on synthetic data; real-log lab check on a system the author owns.

## Risks and responses
| Risk | Response |
|---|---|
| Ollama or model too slow or heavy | Smaller tag (for example `gemma4:e2b`, or a Gemma 3 4B or 1B tag), shorter brief, `FakeLLM` for development; report the hardware |
| TabPFN license or login friction | Human completes it once; otherwise cut-line 1 |
| Agent quota or context limits | Resume prompt (see master prompt file); `BUILD_LOG.md` and the Task List carry state |
| Scope creep | Phase exit criteria and freeze; stretch only after P4 criteria |
| Results too good or too bad | Too good: harder generator. Too bad: diagnose and publish; it is better story material |
| Hardened ASR not zero | Report it, keep the cases, explain the residual risk |
| Time zone mistake on the deadline | Convert 11:59 PM PDT Oct 25 to local time now and write it down |
