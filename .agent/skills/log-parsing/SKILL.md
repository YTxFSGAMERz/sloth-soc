---
name: log-parsing
description: Parse and normalize server logs (sshd/auth.log, nginx access logs, fail2ban, ufw kernel lines) into typed Sloth SOC events. Use this whenever you write or change a log parser, handle syslog timestamps or timezones, read rotated or gzipped logs, deal with malformed or hostile log lines, compute parse coverage, or write fixtures and fuzz tests for parsing. Trigger on phrases like "ingest the logs", "parse auth.log", "read nginx logs", "add a parser", or "why didn't this line parse".
---

# Log parsing for Sloth SOC

Turn raw log lines into typed `Event` objects without crashing, trusting, or hoarding anything. Features, detectors, and the LLM are only as honest as this layer, and every free-text field in a log can be written by an attacker.

## Contract

- Parsers live in `src/sloth_soc/parsers/` (`sshd.py`, `nginx.py`, `fail2ban.py`, `ufw.py`) and share one signature: `parse_line(line, ctx) -> Event | Unparsed`. Bad input produces `Unparsed(reason)`, never an exception.
- `Event` is defined once, in `schema.py`: `id, ts, source, kind, host, src_ip, user, port, method, path, status, ua, bytes, invalid_user, truncated, raw_ref`.
- `ts` is timezone-aware UTC. `kind` is one of `auth_fail, auth_ok, invalid_user, disconnect, http_req, ban, unban, fw_block`.
- `raw_ref = (file, line_no)`. Keep the pointer, not the raw line: a human can open the file at that line, and nothing downstream needs the original text again.
- `id` = first 12 hex chars of `sha1(source|file|line_no|ts)`. Deterministic ids keep reruns, tests, and evidence links stable.
- Only `auth_fail` counts as an attempt. `invalid_user` lines ("Invalid user X from ...") feed the distinct-user features but are not extra attempts, otherwise one probe is counted twice.

## Formats (fixtures use RFC 5737 TEST-NET addresses, never real IPs)

```text
Oct 21 03:12:45 lab-vps sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52344 ssh2
Oct 21 03:12:47 lab-vps sshd[1234]: Failed password for root from 203.0.113.5 port 52346 ssh2
Oct 21 03:13:02 lab-vps sshd[1250]: Invalid user test from 203.0.113.5 port 52350
Oct 21 03:13:03 lab-vps sshd[1250]: Connection closed by authenticating user root 203.0.113.5 port 52351 [preauth]
Oct 21 03:19:10 lab-vps sshd[1301]: Accepted password for alice from 203.0.113.9 port 41122 ssh2
Oct 21 09:02:11 lab-vps sshd[2201]: Accepted publickey for alice from 198.51.100.7 port 50222 ssh2: ED25519 SHA256:abc
2026-10-21T03:12:45.123456+00:00 lab-vps sshd[1234]: Failed password for root from 203.0.113.5 port 52344 ssh2
203.0.113.5 - - [21/Oct/2026:03:14:01 +0000] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible)"
203.0.113.77 - - [21/Oct/2026:03:15:00 +0000] "\x16\x03\x01\x02" 400 150 "-" "-"
2026-10-21 03:12:50,123 fail2ban.actions        [999]: NOTICE  [sshd] Ban 203.0.113.5
Oct 21 03:20:01 lab-vps kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.44 DST=192.0.2.10 PROTO=TCP SPT=40000 DPT=3389
```

Also support IPv6 (use `2001:db8::/32` in fixtures), `pam_unix(sshd:auth): authentication failure; ... rhost=...` lines, and `maximum authentication attempts exceeded`.

## Timestamps

- Syslog lines (`Oct 21 03:12:45`) carry no year and no zone. Take the year from `ctx.year_hint` (file mtime) and the zone from config (default UTC). If the result lands more than 7 days in the future, subtract one year; that handles December logs read in January.
- ISO-8601 and nginx `%z` timestamps carry an offset: convert to UTC.
- Warn (do not fail) when time jumps backwards by more than an hour inside one file.

## Sanitization at parse time

Call the shared `sanitize.clean_field(value, max_len)` on every free-text field (`user, path, ua, host, referrer`) before the `Event` is built.

- Strip C0/C1 control characters, ANSI escape sequences, bidi overrides (U+202A to U+202E, U+2066 to U+2069) and zero-width characters (U+200B to U+200D, U+2060, U+FEFF).
- Cap lengths (user 64, host 64, path 160, ua 120) and set `truncated=True` when cut.
- Record whether anything was stripped (`had_control_chars`); the injection rule R8 uses it.
- Never put these values into a shell command, `eval`, or an f-string that becomes a path.

Why: a username can carry a newline that forges a second log line, an escape sequence that rewrites the analyst's terminal, or text that talks to an LLM. See the `prompt-injection-defense` skill.

## Robustness checklist

- Read files as bytes, decode with `errors="replace"`, stream line by line, and handle `.gz` and rotated names (`auth.log.1`, `auth.log.2.gz`).
- Validate IPs with `ipaddress.ip_address`; strip IPv6 zone ids (`%eth0`); an invalid IP becomes `Unparsed("bad_ip")`.
- nginx: malformed request lines (`"-"`, binary TLS handshakes sent to port 80, `PRI * HTTP/2.0`), 10 KB URLs, quotes inside the user agent.
- sshd: "invalid user" appears in several message shapes. Support at least `Failed password`, `Invalid user`, `Accepted (password|publickey|keyboard-interactive)`, `Connection closed by authenticating user`, `Disconnected from (invalid|authenticating) user`, `maximum authentication attempts exceeded`.
- fail2ban: `Found`, `Ban`, `Unban`, `Restore Ban`, with jail names. ufw: parse `key=value` pairs, tolerate missing keys, handle `[UFW AUDIT]`.

## Parse statistics

Every run produces `ParseStats(lines, parsed, unparsed_by_reason)`. Print it in `doctor` and `run`, and put `parse_coverage` in the digest footer. Silent drops are how detectors go blind without anyone noticing.

## Tests (write them with the parser, not after)

1. Golden tests: at least six hand-written lines per parser, including two hostile ones (newline injection, ANSI escapes). Keep these independent of the synthetic generator; a mistake shared by both would otherwise pass silently.
2. Fuzz test with `hypothesis` (`st.binary()` and `st.text()`): parsers never raise.
3. Round trip: generator output parsed back gives counts equal to the generator's ground truth, with `parse_coverage >= 0.99` on synthetic logs.
4. Timestamp tests: year rollover, timezone offsets, UTC conversion.

## Common mistakes

Using `datetime.now().year` for old files; counting one failed login twice; splitting on whitespace when usernames can contain spaces; storing raw lines "just in case"; letting one bad line abort a whole file.
