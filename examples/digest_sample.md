# Sloth SOC Digest: 2026-10-21 (`srv-prod-01`) — STATUS: URGENT

**TL;DR:** Critical security event detected from 203.0.113.197. Immediate credential and authentication verification required.

## NEEDS YOUR ATTENTION (5)

### F1. [CRITICAL] `203.0.113.197` — Ssh Success After Failures
- **Window:** 2026-10-21 UTC
- **Analysis:** 203.0.113.197: [R1] Brute-force burst: 14 failures in 5 minutes (threshold >= 10) (not blocked).
- **Recommended Action:** Confirm whether this login was expected and authorized.
- **Evidence:** data\synthetic_demo\auth.log:542 | data\synthetic_demo\auth.log:543 | data\synthetic_demo\auth.log:544 | data\synthetic_demo\auth.log:545 | data\synthetic_demo\auth.log:546

### F2. [HIGH] `203.0.113.105` — Web Probe Exposed Path
- **Window:** 2026-10-21 UTC
- **Analysis:** 203.0.113.105: [R3b] Web probing: 5 probe hits, and 1 sensitive path(s) returned HTTP 200! (not blocked).
- **Recommended Action:** Review web server access logs to verify sensitive endpoints are secured.
- **Evidence:** data\synthetic_demo\nginx\access.log:9650 | data\synthetic_demo\nginx\access.log:9651 | data\synthetic_demo\nginx\access.log:9652 | data\synthetic_demo\nginx\access.log:9653 | data\synthetic_demo\nginx\access.log:9654

### F3. [MEDIUM] `203.0.113.81` — Web Path Probing
- **Window:** 2026-10-21 UTC
- **Analysis:** 203.0.113.81: [R3] Web probing: 7 hits on sensitive endpoints (all error status) (not blocked).
- **Recommended Action:** Review web server access logs to verify sensitive endpoints are secured.
- **Evidence:** data\synthetic_demo\nginx\access.log:9543 | data\synthetic_demo\nginx\access.log:9544 | data\synthetic_demo\nginx\access.log:9545 | data\synthetic_demo\nginx\access.log:9546 | data\synthetic_demo\nginx\access.log:9547

### F4. [MEDIUM] `198.51.100.225` — Low And Slow Ssh
- **Window:** 2026-10-21 UTC
- **Analysis:** 198.51.100.225: [R7] Low-and-slow SSH probing: 24 attempts spread across 24 hours without burst (not blocked).
- **Recommended Action:** Review authentication logs for surrounding unauthorized access attempts.
- **Evidence:** data\synthetic_demo\auth.log:541 | data\synthetic_demo\auth.log:557 | data\synthetic_demo\auth.log:559 | data\synthetic_demo\auth.log:575 | data\synthetic_demo\auth.log:584

### F5. [MEDIUM] `203.0.113.37` — Prompt Injection Attempt
- **Window:** 2026-10-21 UTC
- **Analysis:** 203.0.113.37: [R8] Hostile injection pattern: 11 prompt-injection or exploit markers in untrusted fields (not blocked).
- **Recommended Action:** Review authentication logs for surrounding unauthorized access attempts.
- **Evidence:** data\synthetic_demo\auth.log:604 | data\synthetic_demo\auth.log:605 | data\synthetic_demo\auth.log:606 | data\synthetic_demo\auth.log:607 | data\synthetic_demo\auth.log:608

## HANDLED WHILE YOU SLEPT (2)

2 suspicious source addresses were automatically blocked or dropped by edge rules.
- `198.51.100.54`: ssh brute force burst (blocked)
- `203.0.113.92`: port scan (blocked)

## NOISE IGNORED

Handled 2 blocked noise items across 1643 lines of server logs.

---
**Footer:** 1,643 lines -> 5 items to read (lazy ratio 329:1) | `gemma4:e4b` | narrator=template retries=0 latency=2.1s | detectors: rules stat iforest ensemble | parse coverage 99.8%
