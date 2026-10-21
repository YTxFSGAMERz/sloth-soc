"""Fail2ban log parser."""

from __future__ import annotations

import re

from sloth_soc.parsers.base import ParserContext, parse_timestamp, validate_ip
from sloth_soc.schema import Event, EventKind, RawRef, Unparsed

FAIL2BAN_RE = re.compile(
    r"^(?P<ts>[0-9]{4}-[0-9]{2}-[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}(?:,[0-9]+)?)\s+"
    r"fail2ban\.(?P<module>\w+)\s*\[[0-9]+\]:\s*"
    r"(?P<level>[A-Z]+)\s+"
    r"\[(?P<jail>[^\]]+)\]\s+"
    r"(?P<action>Ban|Restore Ban|Unban|Found)\s+"
    r"(?P<ip>\S+)"
)


class Fail2banParser:
    """Parser for Fail2ban activity logs."""

    def parse_line(self, line: str, line_no: int, ctx: ParserContext) -> Event | Unparsed:
        line = line.replace("\r", "").replace("\n", "")
        raw_ref = RawRef(file=ctx.file_path, line_no=line_no)
        snippet = line[:80].strip()

        if not line.strip():
            return Unparsed(reason="empty_line", raw_ref=raw_ref, snippet="")

        m = FAIL2BAN_RE.search(line)
        if not m:
            return Unparsed(reason="unmatched_fail2ban_format", raw_ref=raw_ref, snippet=snippet)

        ts_raw = m.group("ts")
        ts = parse_timestamp(ts_raw, year_hint=ctx.year_hint)
        if not ts:
            return Unparsed(reason="invalid_timestamp", raw_ref=raw_ref, snippet=snippet)

        raw_ip = m.group("ip")
        ip = validate_ip(raw_ip)
        if not ip:
            return Unparsed(reason="bad_ip", raw_ref=raw_ref, snippet=snippet)

        action = m.group("action")
        kind: EventKind
        if action in ("Ban", "Restore Ban"):
            kind = "ban"
        elif action == "Unban":
            kind = "unban"
        elif action == "Found":
            kind = "auth_fail"
        else:
            return Unparsed(reason="unhandled_fail2ban_action", raw_ref=raw_ref, snippet=snippet)

        ev_id = Event.generate_id("fail2ban", ctx.file_path, line_no, ts)

        return Event(
            id=ev_id,
            ts=ts,
            source="fail2ban",
            kind=kind,
            host=ctx.default_host,
            src_ip=ip,
            raw_ref=raw_ref,
        )
