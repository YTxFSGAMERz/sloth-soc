# Sloth SOC: Threat Model

## 1. What we protect
- **Confidentiality of logs:** IPs, usernames, hostnames, timing, and any secrets that leak into URLs or user agents.
- **Integrity of the digest:** the human must not be misled about what happened.
- **The analyst's workstation:** viewing a digest must not run code, fetch URLs, or alter the terminal.
- **Availability:** a hostile log must not crash or stall the nightly job.

## 2. Adversaries
- **Opportunistic internet attacker (primary):** scans and brute-forces constantly; controls usernames, user agents, paths, and referrers of requests it sends.
- **Targeted attacker:** has read the project's source, knows it uses an LLM narrator, and crafts log text to silence or mislead it.
- **Local curious user (low):** can read digest files on disk; out of scope beyond sensible file permissions.

Not modeled: a compromised host or kernel, tampering with log files after the fact, a malicious model checkpoint (verify downloads from official sources), nation-state capabilities.

## 3. Trust boundaries
```text
 Internet  ──(untrusted bytes)──► log files ──► [parser + sanitizer] ──► trusted typed data
 trusted typed data ──► features/detectors (code) ──► findings (trusted)
 findings ──► brief ──► [LLM: untrusted behavior] ──► [validator] ──► renderers ──► human
```
Everything the attacker can write is untrusted until sanitized and typed. The LLM's output is untrusted until validated. Only deterministic code assigns severity, status, entities, and actions.

## 4. Threats and mitigations
| ID | Threat | Vector | Impact | Mitigation | Test |
|---|---|---|---|---|---|
| T1 | Prompt injection to silence or distort the digest | username, UA, path, referrer text read by the LLM | missed incident | D2 no raw untrusted text in brief; D3 schema; D4 deterministic status; D5 validator; D8 fallback | `redteam` P1-P4, P9 |
| T2 | Log forging | newline or CR inside a field creating fake lines | fake or hidden events | strip control chars at parse; parse per physical line only; no re-parsing of field values | forged-line unit test |
| T3 | Terminal escape injection | ANSI or OSC sequences in fields printed to the console | analyst deception | strip ESC and C0/C1; rich markup off for untrusted text | terminal-output test |
| T4 | Markup exfiltration | markdown image, `<img>`, link in digest that auto-fetches | data leak when digest is viewed | no markdown rendering of model text; autoescape; CSP `default-src 'none'`; URL ban in validator | HTML test, P5 |
| T5 | Dangerous recommendations | injected "run this command" text | analyst runs attacker command | enum actions mapped to reviewed sentences; V5 shell-fragment ban | P6 |
| T6 | Resource exhaustion | huge fields or floods inflating context and runtime | stall or truncation | length caps; finding budget K; explicit `num_ctx`; timeouts; stream parsing | P8, large-file test |
| T7 | Unicode disguise | bidi, zero-width, homoglyphs hide meaning | misleading display | strip bidi and zero-width; store `had_control_chars`; R8 flags | sanitize tests |
| T8 | Hallucinated facts | model invents IPs, counts, or causes | wrong decisions | V4 grounding to the brief; template fallback; report grounding error rate | E3 |
| T9 | Data egress by misconfiguration | remote LLM host set by mistake; library phoning home | log leakage | loopback-only guard; no telemetry; no-egress test; offline demo | AT-3 |
| T10 | Supply chain | malicious package or model download | compromise | pinned versions; official sources only; license and provenance notes; no runtime installs | manual review |
| T11 | Poisoned baseline | attacker traffic enters "known good" baselines | later attacks look normal | baselines built from earlier days only; require human-confirmed or high-volume benign history; document the limitation | baseline unit test |
| T12 | Sensitive data in digests | secrets in URLs or user agents echoed | leakage on disk or in chat | no raw untrusted strings by default; caps; digests stored locally with restrictive permissions | digest content test |

## 5. Injection taxonomy
The nine families P1-P9 (direct override, authority spoof, schema break, canary following, markup exfiltration, action hijack, forging and escapes, resource abuse and disguise, encoded or multilingual) and the red-team method are specified in the `prompt-injection-defense` skill.

## 6. Residual risk (state this in the post)
- A model can still produce a bland or slightly off sentence that passes validation; the deterministic banner and evidence refs are the safety net.
- Rule-based injection detection (R8) is heuristic and can be evaded or can false-positive on odd but benign strings.
- Detectors can miss novel attack shapes; synthetic evaluation is optimistic.
- No defense here helps if the logs themselves are tampered with before ingestion.

## 7. Security requirements checklist
- [ ] Sanitize before building any `Event`; unit and fuzz tests exist.
- [ ] The brief in hardened mode contains no attacker-controlled free text.
- [ ] Validator rules V1-V7 each have a failing-case test.
- [ ] HTML has CSP, autoescape, no JS, no external URL.
- [ ] No-egress test green; `doctor` reports network status.
- [ ] Red-team results published for all three modes, including failures.
- [ ] `docs/LICENSES.md` lists model and dependency terms.
