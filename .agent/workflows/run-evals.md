---
description: Run Sloth SOC experiments and the red-team suite, regenerate results and figures, and refresh the README results block from files only. Usage: /run-evals or /run-evals E1,E4.
---

# /run-evals

1. Run `sloth-soc doctor` and note hardware, OS, Python, package versions, Ollama version, and model digests.
2. Run `sloth-soc eval --all` (or only the experiments named in the request). Use `--quick` first if the full run would exceed about 45 minutes, then schedule the full run.
3. Run `sloth-soc redteam` for naive, structured, and hardened modes. Do not change payloads or defenses just to make a number look better; if a defense fails, keep the case and open a fix as a separate change.
4. Confirm each `results/<exp>.json` exists with `git_sha`, `hardware`, `versions`, `config`, `n`, and `metrics`. Regenerate figures in `results/figures/`.
5. Regenerate `results/RESULTS.md` and the README block between `<!-- RESULTS:START -->` and `<!-- RESULTS:END -->` with the report script. Never edit those numbers by hand.
6. Compare with the previous results: list what improved, what regressed, and one sentence on why. Anything surprising goes into `BUILD_LOG.md` as potential post material.
7. Sanity checks: detector scores are not suspiciously perfect (if everything is above 0.99, make the generator harder), critical-scenario recall is reported separately, confidence intervals and n are present.
8. Report a short table of headline metrics and any failures.
