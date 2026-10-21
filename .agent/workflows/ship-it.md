---
description: Final verification and packaging for the DEV challenge submission. Clean-clone test, offline proof, docs consistency, post draft from results, and checklist. Usage: /ship-it.
---

# /ship-it

No new features. This workflow only verifies, polishes, and packages.

1. Clean-clone test: clone the repo into a fresh temporary directory, follow the README quickstart literally, and run `sloth-soc demo` and `sloth-soc demo --no-llm`. Fix any README step that fails.
2. Quality gates: `ruff check .`, `ruff format --check .`, `pytest -q` (including the no-egress and security tests). CI workflow file present.
3. Offline proof: run the demo with the network disabled, capture the terminal output and a screenshot, and save them under `docs/assets/`.
4. Numbers audit: every figure in README and `docs/POST_DRAFT.md` must match a file in `results/`. List any number without a source and fix or remove it.
5. Docs consistency: `docs/SPEC.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, and `EVALUATION_PLAN.md` match the code as built. Update them or log the deviation in `DECISIONS.md`. Ensure `docs/LICENSES.md` lists code, dependency, and model terms (verified from official pages).
6. Screenshots and demo assets: use the browser tool to open the HTML digest and capture the cover image and figures. Check that no real hostnames, IPs, or personal data appear.
7. Post: generate or refresh `docs/POST_DRAFT.md` using the `devto-post-writer` skill, only from real results. Mark every spot where the human author must add their own voice or reactions.
8. Walk through `docs/SUBMISSION_CHECKLIST.md`, tick what is true, and list what remains for the human (publishing, partner promos, final edit, video).
9. Tag `v0.1.0` and summarize the state in `BUILD_LOG.md`.
