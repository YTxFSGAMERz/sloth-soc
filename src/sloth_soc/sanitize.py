"""Log sanitization and injection detection heuristics.

Strips ANSI escapes, C0/C1 control codes, bidi overrides, and zero-width chars.
Caps field lengths and flags anomalies for Rule R8.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Regex matching ANSI escape sequences
ANSI_ESCAPE_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Bidi override characters (U+202A-202E, U+2066-2069)
BIDI_CHARS = set(
    "\u202a\u202b\u202c\u202d\u202e"  # LRE, RLE, PDF, LRO, RLO
    "\u2066\u2067\u2068\u2069"  # LRI, RLI, FSI, PDI
)

# Zero-width characters (U+200B-200D, U+2060, U+FEFF)
ZERO_WIDTH_CHARS = set(
    "\u200b\u200c\u200d"  # ZWSP, ZWNJ, ZWJ
    "\u2060\ufeff"  # Word joiner, BOM / ZWNBSP
)

# Standard length caps
FIELD_CAPS: dict[str, int] = {
    "user": 64,
    "host": 64,
    "path": 160,
    "ua": 120,
    "referrer": 160,
    "default": 256,
}

# Heuristic patterns for prompt injection attempts (Rule R8)
INJECTION_KEYWORDS = [
    r"\bignore\b",
    r"\bdisregard\b",
    r"\bsystem\s*:",
    r"\bassistant\s*:",
    r"\byou are\b",
    r"\brespond with\b",
    r"\ball clear\b",
    r"\bdo not report\b",
    r"\bcanary-[a-z0-9]+\b",
    r"\btreat all\b",
    r"\bpolicy updated\b",
]

INJECTION_KEYWORD_RES = [re.compile(pat, re.IGNORECASE) for pat in INJECTION_KEYWORDS]

MARKUP_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"<\s*img", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"\]\s*\("),  # Markdown link / image target
    re.compile(r"```"),  # Code fence
    re.compile(r"\{\{"),  # Template injection
    re.compile(r"\}\}"),
]

SHELL_PATTERNS = [
    re.compile(r"\|\s*sh\b", re.IGNORECASE),
    re.compile(r"\|\s*bash\b", re.IGNORECASE),
    re.compile(r"\bcurl\s+http", re.IGNORECASE),
    re.compile(r"\bwget\s+http", re.IGNORECASE),
    re.compile(r"\bsudo\s+", re.IGNORECASE),
    re.compile(r"\brm\s+-[rf]+", re.IGNORECASE),
]


@dataclass(frozen=True)
class CleanResult:
    """Result of sanitizing an untrusted field."""

    cleaned: str
    had_control_chars: bool
    truncated: bool


def clean_field(
    value: str | None,
    max_len: int | None = None,
    field_name: str = "default",
) -> CleanResult:
    """Sanitize an untrusted log field at parse time.

    - Strips ANSI sequences
    - Strips C0/C1 control codes (including CR/LF to prevent log injection)
    - Strips Unicode bidi overrides and zero-width spaces
    - Enforces length caps
    """
    if value is None:
        return CleanResult(cleaned="", had_control_chars=False, truncated=False)

    had_control = False

    # 1. Strip ANSI escape sequences
    if "\x1b" in value:
        cleaned_ansi = ANSI_ESCAPE_RE.sub("", value)
        if cleaned_ansi != value:
            had_control = True
        value = cleaned_ansi

    # 2. Filter out control characters, bidi, zero-width
    chars: list[str] = []
    for ch in value:
        code = ord(ch)
        # C0 controls (0x00 - 0x1F) and DEL (0x7F)
        # C1 controls (0x80 - 0x9F)
        # We explicitly strip \r and \n to prevent log forging
        if (0 <= code <= 0x1F) or (0x7F <= code <= 0x9F):
            had_control = True
            continue
        if ch in BIDI_CHARS or ch in ZERO_WIDTH_CHARS:
            had_control = True
            continue
        chars.append(ch)

    cleaned = "".join(chars)

    # 3. Enforce length cap
    cap = max_len if max_len is not None else FIELD_CAPS.get(field_name, FIELD_CAPS["default"])
    truncated = False
    if len(cleaned) > cap:
        cleaned = cleaned[:cap]
        truncated = True

    return CleanResult(cleaned=cleaned, had_control_chars=had_control, truncated=truncated)


def detect_injection_markers(text: str, had_control_chars: bool = False) -> int:
    """Count heuristic prompt injection or malicious pattern hits.

    Used by Rule R8 to flag injection-bearing attacks.
    """
    if not text:
        return 1 if had_control_chars else 0

    hits = 1 if had_control_chars else 0

    # Keyword hits
    for pat in INJECTION_KEYWORD_RES:
        if pat.search(text):
            hits += 1

    # Markup hits
    for pat in MARKUP_PATTERNS:
        if pat.search(text):
            hits += 1

    # Shell fragment hits
    for pat in SHELL_PATTERNS:
        if pat.search(text):
            hits += 1

    # Sentence-like or unusually structured usernames
    if len(text) > 30 and (" " in text or "." in text):
        hits += 1

    return hits
