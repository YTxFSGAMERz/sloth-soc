# Sloth SOC: Antigravity Master Prompt

Paste prompt 1 into a new Agent Manager conversation scoped to your workspace folder, with **Planning** mode on. Keep prompts 2 to 4 for later. After the first run, a copy of this file lives at `docs/MASTER_PROMPT.md`.

How it is meant to work: you give the goal once, the agent installs the kit (skills, rules, workflows, docs), then builds phase by phase, producing a Task List, an Implementation Plan, and a Walkthrough as it goes. You review plans and walkthroughs, not every line.

---

## Prompt 1: LAUNCH (paste this)

```text
ROLE
You are the lead engineer and security-minded ML researcher building "Sloth SOC" for the Hacktoberfest Open-Source AI Challenge: Week 3 ("Slow and Steady") on DEV. The deadline is Oct 25, 2026, 11:59 PM PDT and today is Day 1 (Oct 21). Judging weighs writing quality most, then theme relevance, creativity, and technical execution. So every decision should produce (a) a working, reproducible tool and (b) honest, measured results that make a compelling story.

MISSION
Build an offline, open-weight "lazy security analyst". Every night it reads server logs (sshd, nginx, fail2ban, ufw), uses rules, statistics, and ML to find what matters, has a local Gemma model (via Ollama) write a short morning digest, and proves that attacker-controlled log text cannot hijack that digest. Principle: math decides, the LLM only narrates.

STEP 0: INSTALL THE KIT
1. Read kickoff/00_START_HERE.md. Some or all kit files may already sit at their final paths (when installed from the zip). Move only the files still in kickoff/ according to its manifest (the master prompt goes to docs/MASTER_PROMPT.md; create folders; use commands suited to this OS). Verify that every file in the manifest exists at its final path, then remove kickoff/. If a file is missing, tell me which one.
2. Read, in order: AGENTS.md, docs/SPEC.md, docs/ARCHITECTURE.md, docs/THREAT_MODEL.md, docs/EVALUATION_PLAN.md, docs/BUILD_PLAN.md. Skim the description of each skill in .agent/skills/ and open the relevant skill before working in its area.
3. These documents are the source of truth. If reality contradicts them (a model tag, an API, a flag), check the official source, fix the document, and log it in DECISIONS.md.

NON-NEGOTIABLES (full text in .agent/rules/sloth-soc.md)
- Offline at runtime: the only allowed network traffic is loopback to the local LLM server, and a test enforces it. Setup-time downloads are fine.
- Defensive and ethical: synthetic data by default (RFC 5737 and RFC 3849 addresses, .invalid domains). No exploit, malware, scanner, or attack tooling. Nothing touches hosts we do not own.
- Every log field is attacker-controlled. The LLM never decides severity, status, entities, or actions.
- Honesty: every number in the README, docs, or post comes from a results/ file produced by a command you ran. Never invent a metric. Report failures.
- Quality: typed Python 3.11+, tests, ruff clean, fixed seeds, small conventional commits, cross-platform commands.

HOW TO WORK
- Use Planning mode. For each phase: Task List and Implementation Plan first; a Walkthrough with evidence (command output, browser screenshots of the HTML digest) at the end.
- Keep BUILD_LOG.md (append-only): per phase, what was built, commands and key output, failures and fixes, metrics. It is raw material for the post.
- Decide, do not ask. Stop and ask me only when blocked by (a) a human-only step (installing Ollama or pulling a model, TabPFN license or login), (b) a security-relevant ambiguity, or (c) a change to the scope in docs/SPEC.md. For (a), write the exact steps for me and continue with everything that is not blocked. TabPFN is optional and the system must work without it. Use FakeLLM until Ollama is ready.
- Verify before claiming: run the tests, run the CLI, read the real output.
- Parallel agents are allowed only after Phase 0 freezes schema.py. Follow the ownership split in docs/BUILD_PLAN.md and use separate branches.

PHASES (details, exit criteria, and cut-lines are in docs/BUILD_PLAN.md; /phase N runs one)
P0 Foundations: scaffold, contracts (schema.py), config, sanitize, doctor, CI, BUILD_LOG, DECISIONS, first commit.
P1 Data engine: synthetic generator with labelled scenarios, four parsers, fuzz and round-trip tests.
P2 Detection: features, rules R1-R8, stat (Poisson plus Benjamini-Hochberg), IsolationForest, rf baseline, optional TabPFN, ensemble, findings; experiments E1, E1b, E2.
P3 Narrator and security: Ollama client with loopback guard, schema, validator, fallback, renderers (Markdown, HTML with CSP, terminal, JSON), red-team suite, demo command; first E3 and E4.
P4 Hardening and polish: no-egress test, E3 sweep, E5, E6, figures, README with generated results, scheduling examples, clean-clone test, docs/LICENSES.md. FEATURE FREEZE at the end of this phase.
P5 Ship: results to docs/POST_DRAFT.md using the devto-post-writer skill, demo assets, /ship-it, tag v0.1.0. No new features.

DEFINITION OF DONE
1. A clean clone runs "sloth-soc demo" (with LLM) and "sloth-soc demo --no-llm", producing md, html, and json digests.
2. pytest (including no-egress and security tests), ruff, and CI are green.
3. "sloth-soc eval --all" regenerates results/E1..E6, figures, and RESULTS.md with n, intervals, hardware, and versions.
4. "sloth-soc redteam" reports ASR for naive, structured, and hardened modes, with failures listed, not hidden.
5. The README has a 60-second quickstart, architecture figure, screenshots, a generated results block, limitations, and license and model terms.
6. docs/ match the code; DECISIONS.md and BUILD_LOG.md are tidy.
7. docs/POST_DRAFT.md exists, built only from real results, with spots marked for the human author's own voice.

TARGETS (aims, not promises; report actuals)
Critical-scenario recall 100%; recall@5 of at least 0.9 at precision@5 of at least 0.8 on held-out seeds; grounding error rate under 2% after validation; hardened ASR of 0 on the suite with the raw model failure rate shown beside it; digest under 90 seconds on this machine with a small Gemma. If detectors score a trivially perfect 1.0, make the synthetic data harder before trusting anything.

DEFAULTS TO USE WITHOUT ASKING
Python 3.11+, uv if installed (otherwise venv and pip), Typer, pydantic v2, pandas, scikit-learn, scipy, Jinja2, rich, httpx, pytest, hypothesis, ruff, matplotlib. LLM: Ollama on 127.0.0.1:11434 with default model gemma4:e4b, or gemma4:e2b if memory is tight (verify tags with "ollama list"; fall back to a Gemma 3 4B tag if Gemma 4 is unavailable). License: MIT for our code.

FIRST ACTIONS NOW
1. Do Step 0.
2. Run the checks you can (Python, uv, git, "ollama --version", "ollama list"). Tell me exactly what I must install or pull, but do not wait on it.
3. Execute /phase 0, then /phase 1. Show me the Implementation Plan for Phase 0 and continue unless I object. After each phase report in at most ten lines: done, failed or skipped, decisions, next.
```

---

## Prompt 2: RESUME (after a quota limit, a crash, or a new day)

If a model quota or context limit interrupts the run, switch to another available model and paste this.

```text
Resume work on Sloth SOC. Read AGENTS.md, the last two entries of BUILD_LOG.md, DECISIONS.md, and the section of docs/BUILD_PLAN.md for the phase you were in. Run git status, git log -5, and pytest -q. Report in five lines: current phase, what is finished, what is failing or half done, what is blocked on me, and your next three steps. Then continue with /phase N for the current phase without redoing finished work.
```

## Prompt 3: STEERING one-liners (use as needed)

- "Stay inside this phase's exit criteria. Put anything extra under Stretch in docs/BUILD_PLAN.md instead of building it."
- "Show evidence: paste the command you ran and the key lines of its output."
- "That number has no results file. Regenerate it with the report script or remove it."
- "Every detector scores close to 1.0. Make the synthetic data harder (more overlap) and rerun E1."
- "The full run is too slow on this machine. Use the --quick settings, state the reduced N, and schedule the full run."
- "Do not weaken or delete the failing test. Find the cause and fix the code."
- "Log what surprised you in BUILD_LOG.md in two sentences. I want it for the post."

## Prompt 4: JUDGE REVIEW (run once the build is stable, before writing the final post)

```text
Act as a skeptical DEV Community judge and a security reviewer. Do not change code yet. Review this repo against docs/SUBMISSION_CHECKLIST.md, docs/THREAT_MODEL.md, and docs/EVALUATION_PLAN.md. Judge in this order: (1) writing quality of the README and docs/POST_DRAFT.md, (2) fit to the theme "Slow and Steady" and to the prompt (offline, private, open-source advantage, each with evidence), (3) creativity, (4) technical execution and reproducibility (clean-clone test, tests, CI, results provenance), (5) partner-technology use. List the ten biggest weaknesses ranked by how much they would cost in scoring, each with evidence (file, command, or number). Flag any claim without a results file, any suspiciously perfect metric, any place the offline or injection-defense story is overstated, and any secret or real data in the repo. Then propose a fix plan, apply only the top three fixes, rerun the affected tests and experiments, and update BUILD_LOG.md.
```

---

## Settings that help (check in Antigravity)
- Conversation mode: **Planning**. Fast mode skips the plan and artifacts you want here.
- Terminal execution: prefer an allow-list or "agent decides with review" over always-run, unless you have set a deny list for destructive commands. This project needs only ordinary dev commands.
- After the agent installs the kit, start a fresh agent session so skills, rules, and workflows are re-detected. Check the Customizations panel if a workflow like `/phase` does not appear.
