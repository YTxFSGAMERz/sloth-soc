# Sloth SOC: DEV Post Outline

Use this as the skeleton for `docs/POST_DRAFT.md`. Fill every `[RESULT: ...]` from `results/` or `BUILD_LOG.md`; delete anything you cannot back up. The author edits the final text into their own voice. Read the `devto-post-writer` skill first.

## Title options (pick one, test it aloud)
- The Day an SSH Username Tried to Prompt-Inject My Security Tool
- I Built a Lazy Security Analyst That Runs Offline and Can't Be Sweet-Talked by Attackers
- Sloth SOC: Math Decides, a Local Gemma Narrates, Attackers Get Ignored
- Slow and Steady Security: An Offline Log Analyst That Works While You Sleep

## Submission template block
Use the DEV challenge submission template (it adds `devchallenge` and `hf26challenge`). Add up to two more tags, for example `cybersecurity` and `ai`. Cover image about 1000 by 420 px: the digest screenshot or the architecture figure.

## Skeleton (target 1,800 to 2,600 words)

### 1. Hook (3 to 5 sentences)
Open with the strange log line, shown in a code block, then what it tried to do. Then: "My tool ignored it. Here's how, and the numbers." [RESULT: payload text from the red-team suite]

### 2. The lazy problem
Nobody reads logs. Sending them to a cloud LLM leaks IPs, usernames, and hostnames. One sentence on the sloth theme: set it up once, let it work while you sleep. Lazy payoff: [RESULT: E6 lazy ratio, raw lines to items to read; assumptions stated].

### 3. The idea in one sentence
Math and ML decide what matters. A local open-weight model only narrates. Everything it says is checked.

### 4. What it looks like
Digest screenshot (F2) and the 60 to 90 second demo. [RESULT: model name, hardware, digest latency cold and warm from E3]

### 5. How it works
Architecture figure (F1). Three design choices, each with a why and a trade-off:
- IP-day as the unit of analysis (low-and-slow scanners become visible).
- Enum actions and deterministic status (a hijacked model can't change the banner or write commands).
- A validator between model and reader (grounding, forbidden patterns, status match).
Include one short code excerpt: the validator rule or the loopback guard.

### 6. I attacked my own tool
Describe the nine injection families in two sentences, then the table: `naive` vs `structured` vs `hardened`. [RESULT: E4 ASR with intervals, raw LLM failure rate, fallback rate]. Tell the story of one failure that surprised you and what fixed it (pull from `BUILD_LOG.md`). Mention that the tool flags injection attempts as findings (R8). Be explicit about scope: synthetic data, inert payloads, own pipeline only.

### 7. Does it find the right things?
Heatmap (F3): detector by scenario. [RESULT: E1 critical recall, recall@5 and precision@5, shift-set delta from E1b]. TabPFN label-efficiency curve (F4). [RESULT: E2]. If TabPFN did not win, say so and explain why that is still useful.

### 8. Slow and steady (the model-size experiment)
The reader is asleep, so latency matters less than faithfulness. Plot or table: Gemma sizes against latency and grounding errors (F6). [RESULT: E3]. One honest sentence about hardware.

### 9. Why open mattered
Each claim paired with evidence:
- Offline: network-off run and the passing no-egress test (F7).
- Private: logs never leave the machine; the LLM client refuses non-loopback hosts.
- Swappable: changed the model by editing one config line; show the diff and the results.
- Free to run: no per-token fees; electricity only.
- Inspectable: could test and attack every layer, which is how the injection defense got built.

### 10. Limits and what's next
Synthetic data written by the same author; small scale; no adaptive adversary; heuristic R8. Next: [stretch items actually planned].

### 11. Try it
Repo link, three-command quickstart, license and model terms note, thanks.

## Figures checklist
F1 architecture. F2 before and after. F3 detector-by-scenario heatmap. F4 label efficiency. F5 ASR bars. F6 model size vs latency and faithfulness. F7 offline proof. Each caption states the takeaway.

## Demo script (60 to 90 s)
0:00 show the injection log line; say what it tries to do. 0:10 turn Wi-Fi off; run `sloth-soc demo`. 0:30 open the digest; read the TL;DR. 0:50 show the red-team table. 1:10 one-line close and repo link. 1080p, large terminal font, nothing personal visible.

## Style reminders
First person, concrete, short paragraphs. Show output first, interpret after. No hype words. Humor light. State assumptions next to every estimate. Admit what failed.

## Before you publish
- Every number traces to `results/`. - Aloud read-through done. - Links tested in a private window. - README quickstart works from a clean clone. - Tags and template correct. - Challenge FAQ on AI use re-read. - Screenshots contain no real hostnames or personal data.
