# Sloth SOC: Architecture

## 1. Shape of the system
```text
 logs ──► parsers ──► sanitize ──► Events ──► features ──► detectors ──► ensemble
 sshd                 (strip control,        (per IP-day,    rules R1-R8     │
 nginx                 cap length)            multi-scale)   stat (Poisson+BH)│
 fail2ban                                                    iforest         ▼
 ufw                                                         tabpfn (opt)   ranked findings (JSON)
                                                                             │  deterministic: severity,
                                                                             │  status, entities, actions
                         ┌───────────────────────────────────────────────────┤
                         ▼                                                   ▼
              brief (derived facts only)                      template narrator (fallback)
                         │                                                   ▲
                         ▼                                                   │ fail x3 / --no-llm
              local LLM (Gemma via Ollama, loopback)  ──► validator ─────────┘
              JSON-schema constrained                       │ pass
                                                            ▼
                                       renderers: Markdown | HTML (CSP, no JS) | JSON | terminal
```
Everything left of the "brief" is deterministic and testable without a model. The LLM sits in a narrow, validated corridor.

## 2. Modules (`src/sloth_soc/`)
| Module | Responsibility |
|---|---|
| `schema.py` | Pydantic contracts: `Event`, `FeatureRow`, `Finding`, `Brief`, `DigestMeta`, `ParseStats`. Frozen after Phase 0 |
| `config.py` | YAML to typed settings; secure defaults (loopback-only LLM) |
| `sanitize.py` | `clean_field`, control/ANSI/bidi/zero-width stripping, length caps, injection-marker heuristics |
| `parsers/` | One parser per source, shared `parse_line` contract, `ParseStats` |
| `state.py` | SQLite: known users, known source IPs, hourly baselines |
| `features.py` | IP-day feature table |
| `detectors/` | `base.py` protocol, `rules.py`, `stat.py`, `iforest.py`, `tabpfn_det.py`, `ensemble.py` |
| `findings.py` | Ranked IP-days to `Finding` objects; attention budget; "handled" grouping |
| `llm/` | `client.py` (Ollama, optional OpenAI-compatible), `prompts.py`, `schema.py`, `validator.py`, `fallback.py`, `fake.py` |
| `render/` | `markdown.py`, `html.py` (+ `templates/digest.html.j2`), `terminal.py` |
| `synth/` | Scenario generator, payload library, labels |
| `evalkit/` | Metrics, experiments E1-E6, figures, report writer, README block injector |
| `redteam/` | Suite definition and runner for the three pipeline modes |
| `cli.py` | Typer commands |

## 3. Data contracts (summary; `schema.py` is authoritative)
- **Event:** `id, ts(UTC), source, kind, host, src_ip, user, port, method, path, status, ua, bytes, invalid_user, truncated, raw_ref(file, line_no)`.
- **FeatureRow:** `(src_ip, day)` plus the feature columns listed in the `anomaly-detection` skill. Labels and scenario names live outside this object.
- **Finding:** `id, severity(info|low|medium|high|critical), kind, entity, window, evidence{...}, reasons[...], evidence_refs[<=20], blocked, score`.
- **Brief:** `date, status(quiet|attention|urgent), stats, findings[<=K]` with derived facts only in hardened mode.
- **Status rule (deterministic):** `urgent` if any critical; `attention` if any high or medium inside the budget; else `quiet`.

## 4. Nightly run (sequence)
1. Discover files for the target day (including rotated and gz). 2. Parse and sanitize, emit `ParseStats`. 3. Update state baselines (known users and IPs) from earlier days only, so today's attacker never trains its own baseline. 4. Build features. 5. Run detectors, ensemble, build findings. 6. Build brief. 7. Narrate (LLM, validate, retry, fallback). 8. Render and write outputs. 9. Print a terminal summary. Exit code 0 even on fallback; nonzero only if no digest could be produced.

## 5. Decision records
- **ADR-1 IP-day as the unit.** Rows are small, labels are clear, and low-and-slow scanners show up in daily aggregates. Cost: attacks that rotate IPs need cross-IP aggregation (R2 and a stretch feature); same-IP sub-day timing is captured by in-row 5-minute features.
- **ADR-2 The LLM narrates, code decides.** Reduces hallucination to checkable claims and caps the damage of hijacking. Cost: less "magic"; the narrator cannot discover threats the detectors miss.
- **ADR-3 Enum actions.** The model chooses from reviewed actions; it cannot author commands. Cost: less nuanced advice.
- **ADR-4 Hybrid detection.** Rules catch known patterns and give explainable severity; statistics control false discoveries; IsolationForest needs no labels; TabPFN shows what a few labels buy. Cost: more code; offset by the shared `Detector` protocol and one evaluation harness.
- **ADR-5 SQLite and files, no services.** A nightly batch job does not need a database server; fewer moving parts to secure.
- **ADR-6 Loopback-only LLM endpoint.** A misconfiguration cannot send logs off the machine. Overridable only by an explicit flag.
- **ADR-7 Synthetic-first evaluation.** Safe to publish, reproducible, labelled. Cost: optimistic by construction; mitigated by shift seeds, hard cases, and a candid validity section.
- **ADR-8 Slow is fine.** The reader is asleep, so latency matters less than faithfulness; this justifies preferring a larger local model when the hardware allows (tested in E3).

## 6. Failure modes and degradation
| Failure | Behavior |
|---|---|
| Ollama down or model missing | `doctor` explains; run falls back to the template narrator; digest footer says `narrator=template` |
| Validator rejects twice | Template fallback; counted in `fallback_rate` |
| TabPFN unavailable (import, license, weights) | Detector reported `unavailable`; others continue |
| Unparseable lines | Counted by reason; coverage shown in the footer; run continues |
| Log files missing for a source | Source marked `absent`; digest says which sources were read |
| Clock or year ambiguity in syslog | Year inferred from file mtime with rollover rule; warning recorded |

## 7. Extension points
New parser: implement `parse_line`, register in `parsers/__init__.py`, add golden and fuzz tests. New detector: implement the `Detector` protocol; the harness picks it up from config. New backend: implement `LLMClient`; it must pass the same validator. New scenario: add to the generator with a label and truth severity.

## 8. Performance notes
Parsing is streaming and linear. Features use vectorized pandas groupby on the IP-day key. IsolationForest and the stat detector are negligible at this scale. The LLM call dominates: keep the brief small (at most K findings), set `num_ctx` explicitly, keep the model warm with `keep_alive` during evaluation, and measure cold versus warm separately. TabPFN on CPU is slower; cap rows or use the Fast checkpoint and report the setting.
