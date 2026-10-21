"""SSHD authentication log parser."""

from __future__ import annotations

import re

from sloth_soc.parsers.base import ParserContext, parse_timestamp, validate_ip
from sloth_soc.sanitize import clean_field
from sloth_soc.schema import Event, EventKind, RawRef, Unparsed

# Regex matching syslog or ISO prefix for sshd
SSHD_PREFIX_RE = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})|"
    r"(?:[0-9]{4}-[0-9]{2}-[0-9]{2}[T\s][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?))\s+"
    r"(?P<host>[^\s:]+)\s+"
    r"(?:sshd(?:\[[0-9]+\])?:|pam_unix\(sshd:auth\):)\s+"
    r"(?P<msg>.*)$"
)

# Detailed message matchers
FAILED_PW_RE = re.compile(
    r"^Failed password for (?:(?P<invalid>invalid user)\s+)?(?P<user>.+?)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>[0-9]+))?"
)
ACCEPTED_RE = re.compile(
    r"^Accepted\s+(?P<auth_method>password|publickey|keyboard-interactive)\s+for\s+(?P<user>.+?)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>[0-9]+))?"
)
INVALID_USER_RE = re.compile(
    r"^Invalid user\s+(?P<user>.+?)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>[0-9]+))?"
)
DISCONNECT_RE = re.compile(
    r"^(?:Connection closed by (?:authenticating user\s+)?|Disconnected from (?:invalid user\s+)?)"
    r"(?:(?P<user>\S+)\s+)?(?P<ip>\S+)(?:\s+port\s+(?P<port>[0-9]+))?"
)
MAX_ATTEMPTS_RE = re.compile(
    r"^(?:error:\s+)?maximum authentication attempts exceeded for (?:(?P<invalid>invalid user)\s+)?(?P<user>.+?)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>[0-9]+))?"
)
PAM_AUTH_FAIL_RE = re.compile(
    r"^authentication failure;.*?\brhost=(?P<ip>\S+)(?:.*?\buser=(?P<user>\S+))?"
)


class SSHDParser:
    """Parser for OpenSSH auth.log records."""

    def parse_line(self, line: str, line_no: int, ctx: ParserContext) -> Event | Unparsed:
        # Strip CR/LF at the physical line boundary to prevent newline log forging
        line = line.replace("\r", "").replace("\n", "")
        raw_ref = RawRef(file=ctx.file_path, line_no=line_no)
        snippet = line[:80].strip()

        if not line.strip():
            return Unparsed(reason="empty_line", raw_ref=raw_ref, snippet="")

        m = SSHD_PREFIX_RE.match(line)
        if not m:
            return Unparsed(reason="unmatched_sshd_format", raw_ref=raw_ref, snippet=snippet)

        ts_raw = m.group("ts")
        host_raw = m.group("host")
        msg = m.group("msg").strip()

        ts = parse_timestamp(ts_raw, year_hint=ctx.year_hint)
        if not ts:
            return Unparsed(reason="invalid_timestamp", raw_ref=raw_ref, snippet=snippet)

        host_clean = clean_field(host_raw, field_name="host").cleaned or ctx.default_host

        kind: EventKind = "auth_fail"
        raw_user: str | None = None
        raw_ip: str | None = None
        port: int | None = None
        invalid_user = False

        # 1. Failed password
        m_failed = FAILED_PW_RE.match(msg)
        if m_failed:
            kind = "auth_fail"
            raw_user = m_failed.group("user")
            raw_ip = m_failed.group("ip")
            port = int(m_failed.group("port")) if m_failed.group("port") else None
            invalid_user = bool(m_failed.group("invalid"))

        # 2. Accepted login
        elif m_acc := ACCEPTED_RE.match(msg):
            kind = "auth_ok"
            raw_user = m_acc.group("user")
            raw_ip = m_acc.group("ip")
            port = int(m_acc.group("port")) if m_acc.group("port") else None

        # 3. Invalid user announcement
        elif m_inv := INVALID_USER_RE.match(msg):
            kind = "invalid_user"
            raw_user = m_inv.group("user")
            raw_ip = m_inv.group("ip")
            port = int(m_inv.group("port")) if m_inv.group("port") else None
            invalid_user = True

        # 4. Disconnect / closed
        elif m_disc := DISCONNECT_RE.match(msg):
            kind = "disconnect"
            raw_user = m_disc.group("user")
            raw_ip = m_disc.group("ip")
            port = int(m_disc.group("port")) if m_disc.group("port") else None

        # 5. Max authentication attempts
        elif m_max := MAX_ATTEMPTS_RE.match(msg):
            kind = "auth_fail"
            raw_user = m_max.group("user")
            raw_ip = m_max.group("ip")
            port = int(m_max.group("port")) if m_max.group("port") else None
            invalid_user = bool(m_max.group("invalid"))

        # 6. PAM authentication failure
        elif m_pam := PAM_AUTH_FAIL_RE.match(msg):
            kind = "auth_fail"
            raw_ip = m_pam.group("ip")
            raw_user = m_pam.group("user")

        else:
            return Unparsed(reason="unhandled_sshd_message", raw_ref=raw_ref, snippet=snippet)

        ip = validate_ip(raw_ip)
        if not ip:
            return Unparsed(reason="bad_ip", raw_ref=raw_ref, snippet=snippet)

        user_clean = clean_field(raw_user, field_name="user")
        ev_id = Event.generate_id("sshd", ctx.file_path, line_no, ts)

        return Event(
            id=ev_id,
            ts=ts,
            source="sshd",
            kind=kind,
            host=host_clean,
            src_ip=ip,
            user=user_clean.cleaned if raw_user is not None else None,
            port=port,
            invalid_user=invalid_user,
            truncated=user_clean.truncated,
            raw_ref=raw_ref,
        )
