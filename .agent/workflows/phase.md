---
description: Execute one Sloth SOC build phase from docs/BUILD_PLAN.md end to end (plan, implement, test, log, commit). Usage: /phase 0 to /phase 5.
---

# /phase N

1. Read `AGENTS.md`, then the section for phase N in `docs/BUILD_PLAN.md`. Open every skill that section names.
2. Produce a Task List and an Implementation Plan: files to create or change, tests to write, risks, and the exact acceptance commands from the phase's exit criteria.
3. Implement in small steps. Write tests alongside code. Commit after each coherent step with a conventional commit message.
4. Run `ruff check .`, `ruff format --check .`, and `pytest -q`. Fix failures properly; never weaken or delete a test to get green.
5. Run the phase's acceptance commands and read the real output. If an exit criterion fails, fix it or record exactly why in `DECISIONS.md` and apply the cut-line from `docs/BUILD_PLAN.md`.
6. Append a dated entry to `BUILD_LOG.md`: what was built, key commands with short output excerpts, failures and how they were fixed, and a metrics snapshot if any exist.
7. Produce a Walkthrough artifact with evidence (command output, and for rendered digests a browser screenshot).
8. Report in at most ten lines: done, failed or skipped, decisions made, next phase.

Stop and ask only for the conditions listed in the master prompt (human-only step, security ambiguity, scope change).
