---
name: devto-post-writer
description: Draft and polish the DEV Community challenge post for Sloth SOC (Hacktoberfest Open-Source AI Challenge: Week 3, "Slow and Steady") from real results. Use this whenever you write, outline, edit, or review the post, README intro, demo script, figure captions, or submission text, or when asked about judging criteria, storytelling, or what to include. Trigger on "write the post", "DEV article", "submission", "README intro", "demo script", or "make it more compelling". Writing quality is the most heavily weighted criterion, so use this skill before drafting any prose.
---

# Writing the DEV post

Judging weighs writing quality most, then relevance to the prompt and theme, creativity, technical execution, and optional partner technology. The code earns the right to be read; the post decides whether it wins. Write for a smart developer who has never heard of the project and has about five minutes.

## Ground rules

- Every number comes from `results/*.json` or `BUILD_LOG.md`. Trace each one. Never invent or round up a result; say "on my laptop" and name the hardware.
- Draft from `BUILD_LOG.md`: the failures and fixes recorded there are the best material. Save the draft to `docs/POST_DRAFT.md`.
- The human author edits the final version into their own voice, adds their real reactions, and decides what to publish. Before submission, check the challenge FAQ about using AI; whatever it permits, the post must sound like a person who built this.
- The post must answer the prompt directly: what was built, what effort it saves (the lazy payoff), a demo, and why open innovation mattered. Use the DEV submission template, which adds the required `devchallenge` and `hf26challenge` tags (DEV allows four tags, so two are free, for example `cybersecurity` and `ai`).

## Story spine (about 1,800 to 2,600 words)

1. Hook (3 to 5 sentences): an attacker's SSH username tried to give my security tool orders, and the tool ignored it. Open with the strange log line or the digest, not with "In today's world".
2. The pain and the lazy payoff: logs nobody reads, and why sending them to a cloud LLM is a privacy problem. State the payoff as a number: raw lines in, items to read out, time saved with the assumptions shown.
3. The idea in one sentence: math decides, the local model only narrates.
4. What it looks like: the digest screenshot, then a 60 to 90 second demo.
5. How it works: one architecture figure and three design choices, each with a "why" and a trade-off (IP-day unit, enum actions, deterministic status).
6. The attack on my own tool: the red-team results (naive versus structured versus hardened), one failure that surprised you, and the fix. This is the section people will remember.
7. Results: a small table plus two or three figures (detector-by-scenario heatmap, TabPFN label efficiency, model-size latency versus faithfulness). Say what was weak.
8. Why open mattered: concrete, tied to evidence. Offline proof, logs never leaving the machine, swapping Gemma sizes by editing one line, TabPFN few-label results, no per-token bill, being able to inspect and test the whole stack.
9. Limits and what's next: synthetic data, same-author bias, no adaptive adversary. Honest limits raise trust.
10. Try it: repo link, quickstart in three commands, and where to ask questions.

## Style

- First person, concrete nouns, short paragraphs, one idea each. Define a term once, in passing.
- Show, then explain: code or output first, one sentence on what to notice after it.
- Every figure gets a caption that states the takeaway, not the title.
- Humor is welcome and light (a sloth that does the work), never at the expense of clarity.
- Cut: hype words, "revolutionary", rhetorical questions in a row, repeated summaries, features nobody uses in the demo.
- Prefer one strong example per point over three weak ones.

## Figures (generate from `results/figures/` or with the browser tool)

F1 architecture ("math decides, the LLM narrates"); F2 before and after (raw log lines versus one-screen digest); F3 detector-by-scenario recall heatmap; F4 TabPFN label-efficiency curve; F5 ASR bars for naive, structured, hardened; F6 model size versus latency and faithfulness; F7 offline proof (network disabled, run succeeds, no-egress test green). DEV does not render Mermaid reliably; export diagrams as PNG or SVG images, or use an ASCII block. Use a cover image around 1000 by 420 pixels.

## Demo script (60 to 90 seconds)

0:00 show the injection log line and say what it tries to do. 0:10 turn the network off and run `sloth-soc demo`. 0:30 open the digest and read the TL;DR. 0:50 show the red-team table. 1:10 one-line close and the repo link. Record at 1080p, large terminal font, no real hostnames or personal data visible.

## Before publishing

Read the post aloud once. Check every claim against `results/`. Click every link in a private window. Confirm the repo's first commit falls inside the contest window and that the README quickstart works from a clean clone. Confirm tags, cover image, and the challenge template are in place. Then follow `docs/SUBMISSION_CHECKLIST.md`.
