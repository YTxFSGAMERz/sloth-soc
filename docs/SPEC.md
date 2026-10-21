# Sloth SOC: Product Specification

## 1. One-liner
A lazy security analyst that reads your server logs overnight, offline, and leaves a one-screen morning digest of the few things worth your attention.

## 2. Problem
Small teams, students, and home-lab owners run servers that are probed constantly. Nobody reads the logs, and pasting them into a cloud LLM leaks IPs, usernames, hostnames, and sometimes secrets. Worse, log text is attacker-controlled: a username can contain instructions aimed at any AI that reads it.

## 3. Users and stories
- **Solo admin (primary):** "I run a VPS. Tell me each morning if anything needs me, in under a minute."
- **Privacy-minded home-labber:** "My logs must never leave my machine, and it must work with the network off."
- **Security student (the author, and the judges):** "Show me measured results, not vibes, and show me how it survives attacks on itself."
- **Tinkerer:** "Let me swap the model or the detectors with one config change and see what happens."

## 4. Goals and non-goals
Goals: useful digest, offline operation, measurable detection quality, measurable resistance to injection, one-command demo, reproducible evaluation.
Non-goals: replacing a SIEM, real-time alerting, response automation (the tool never blocks or changes anything), multi-host fleets, GUI dashboards, cloud services.

## 5. Functional requirements
| ID | Requirement | Priority |
|---|---|---|
| FR-1 | Ingest sshd, nginx (combined), fail2ban, and ufw logs from files or directories, plain or gzipped, with parse statistics | MUST |
| FR-2 | Normalize to typed events; sanitize all free text at parse time | MUST |
| FR-3 | Compute per-(IP, UTC day) multi-scale features | MUST |
| FR-4 | Detectors: rules R1-R8, `stat` (Poisson + BH), `iforest`, `ensemble`; `tabpfn` optional | MUST (tabpfn SHOULD) |
| FR-5 | Produce ranked findings with severity, evidence refs, blocked flags, reasons | MUST |
| FR-6 | Narrator: local LLM, schema-constrained, validated, with deterministic fallback | MUST |
| FR-7 | Outputs: Markdown, self-contained HTML (CSP, no JS), JSON, terminal view | MUST |
| FR-8 | Synthetic generator with labelled scenarios, seeds, and shift mode | MUST |
| FR-9 | Evaluation harness for experiments E1-E6 writing to `results/` | MUST |
| FR-10 | Red-team suite comparing `naive`, `structured`, `hardened` modes | MUST |
| FR-11 | CLI: `doctor`, `demo`, `run`, `synth`, `eval`, `redteam`; `--no-llm` flag | MUST |
| FR-12 | Scheduling examples: cron, systemd timer, Windows Task Scheduler | SHOULD |
| FR-13 | State in SQLite: known users, known source IPs, hourly baselines | SHOULD |
| FR-14 | `ask` command to query findings in natural language (answers only from findings) | COULD |
| FR-15 | Optional `tone: sloth` narration style | COULD |

## 6. Non-functional requirements
- **NFR-1 Offline:** after setup, no network except loopback to the LLM server; enforced by a test.
- **NFR-2 Privacy:** no telemetry; digests contain only bounded, sanitized fields; nothing leaves the machine.
- **NFR-3 Determinism:** same seed and inputs give the same findings; LLM at temperature 0 with a fixed seed.
- **NFR-4 Performance (targets, report actuals):** pipeline without LLM under 30 s for a 7-day synthetic set; digest under 90 s on a CPU-only laptop with a small model.
- **NFR-5 Portability:** demo and evaluation run on Linux, macOS, and Windows; real-log mode targets Linux log formats.
- **NFR-6 Safe defaults:** loopback-only LLM host, CSP in HTML, autoescaping, control characters stripped.
- **NFR-7 Quality:** typed code, tests (unit, property, integration, security), CI, lint clean.
- **NFR-8 Degradation:** missing LLM, TabPFN, or GeoIP never stops the digest; the footer says what ran.

## 7. CLI
| Command | Purpose |
|---|---|
| `sloth-soc doctor` | Check Python, packages, Ollama reachability (loopback), model availability, TabPFN availability, network-off status; print hardware and versions |
| `sloth-soc demo [--no-llm] [--seed N]` | Generate a synthetic week, run the full pipeline, write a digest, print its path |
| `sloth-soc synth --seed N --days D [--shift] --out DIR` | Generate logs and ground-truth labels |
| `sloth-soc run --config FILE [--date D] [--no-llm]` | Analyze real log files and write the digest |
| `sloth-soc eval --all` or `--exp E1,E4` | Run experiments, write `results/` and figures |
| `sloth-soc redteam [--quick]` | Run the injection suite across the three modes |

## 8. Config (`config.example.yaml`)
```yaml
host_label: lab-vps
timezone: UTC
sources:
  sshd:     {paths: ["/var/log/auth.log*"]}
  nginx:    {paths: ["/var/log/nginx/access.log*"]}
  fail2ban: {paths: ["/var/log/fail2ban.log*"]}
  ufw:      {paths: ["/var/log/ufw.log*"]}
detect:
  attention_budget: 5
  rules: {r1_fail_5m: 10, r2_users: 8, r3_probes: 5, r4_ports: 15}
  tabpfn: {enabled: false}
llm:
  backend: ollama
  host: http://127.0.0.1:11434
  model: gemma4:e4b        # verify the tag with `ollama list`; use gemma4:e2b on small machines
  temperature: 0
  num_ctx: 8192
  think: false
  allow_remote: false
output:
  dir: digests
  formats: [md, html, json]
  tone: plain
```

## 9. Digest format
The mock below is illustrative only. Real digests come from the pipeline.

```text
Sloth SOC digest, 2026-10-21 (host: lab-vps)           STATUS: URGENT
TL;DR  One address logged in as `alice` after 37 failed guesses. Confirm that
       login. Everything else was blocked noise.

NEEDS YOUR ATTENTION (2)
1. CRITICAL F1  203.0.113.9   SSH success after 37 failures (03:12-03:19 UTC)
   Why: 37 wrong passwords against one account, then a success; not blocked.
   Do:  Confirm the login was yours; if not, rotate the account's credentials
        and revoke sessions.
   Evidence: auth.log lines 10412-10450 | rule R5 | isolation-forest top 1%
2. MEDIUM F2  198.51.100.23  Probed 14 sensitive paths, all 404
   Do:  Review the web server logs and confirm the probed paths are not exposed.

HANDLED WHILE YOU SLEPT
12 addresses banned by fail2ban after 1,840 login attempts.

NOISE I IGNORED
3 crawlers and 1 health-check monitor.

Footer: 48,213 lines -> 2 items to read (lazy ratio 24,106:1) | gemma4:e4b |
narrator=llm retries=0 latency=41 s | detectors: rules stat iforest | parse coverage 99.5%
```

## 10. Acceptance tests
- AT-1 `sloth-soc demo` on a clean clone produces `digests/*.md|html|json` and prints the path.
- AT-2 `sloth-soc demo --no-llm` produces the same findings with template narration, under 30 s.
- AT-3 The no-egress test passes: any non-loopback connect or DNS lookup fails the test.
- AT-4 `sloth-soc eval --all` produces `results/E1..E6.json`, figures, and `RESULTS.md`.
- AT-5 `sloth-soc redteam` prints an ASR table for the three modes and the hardened mode never lets a canary, external URL, or contradicted status reach the rendered digest on the suite (failures, if any, are reported rather than hidden).
- AT-6 The HTML digest contains the CSP meta tag and no external URL.
- AT-7 Parsers never raise on fuzzed input; parse coverage on synthetic logs is at least 99%.
- AT-8 Every number in the README results block is generated from `results/*.json`.

## 11. README requirements
Top: one-line pitch, a screenshot of the digest, and 3-4 headline numbers (generated). Then: 60-second quickstart (install, `doctor`, `demo`), architecture figure, "why open" section with evidence, results table (generated block), red-team table, scheduling how-to, limitations and threats to validity, license and model terms, contributing, and a link to the DEV post.

## 12. Stretch (only after the Phase 4 freeze criteria are met)
`ask` command with retrieval limited to findings; optional fine-tune of a small Gemma on synthetic findings-to-digest pairs with Tinker (train on synthetic data in the cloud, run locally on private logs); offline GeoIP enrichment from a user-supplied database; static project page on a `.tech` domain; durable nightly job with Temporal; agent tracing with Sentry on synthetic data only.
