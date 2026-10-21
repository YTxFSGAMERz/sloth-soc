"""Nginx Combined Log Format parser."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from sloth_soc.parsers.base import MONTH_MAP, ParserContext, validate_ip
from sloth_soc.sanitize import clean_field
from sloth_soc.schema import Event, RawRef, Unparsed

# Combined log format regex:
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
NGINX_LOG_RE = re.compile(
    r"^(?P<ip>\S+)\s+"
    r"\S+\s+"  # ident (-)
    r"(?P<user>\S+)\s+"  # auth user or -
    r"\[(?P<ts>[^\]]+)\]\s+"  # timestamp
    r'"(?P<request>.*?)"\s+'  # request line (can be malformed)
    r"(?P<status>[0-9]{3})\s+"  # status code
    r"(?P<bytes>\S+)"  # bytes sent or -
    r'(?:\s+"(?P<ref>.*?)"\s+"(?P<ua>.*?)")?'  # optional referer & user agent
)

# Nginx timestamp format: 21/Oct/2026:03:14:01 +0000
NGINX_TS_RE = re.compile(
    r"^([0-9]{1,2})/([A-Z][a-z]{2})/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2})\s+([+-][0-9]{4})$"
)


class NginxParser:
    """Parser for Nginx access logs."""

    def parse_line(self, line: str, line_no: int, ctx: ParserContext) -> Event | Unparsed:
        line = line.replace("\r", "").replace("\n", "")
        raw_ref = RawRef(file=ctx.file_path, line_no=line_no)
        snippet = line[:80].strip()

        if not line.strip():
            return Unparsed(reason="empty_line", raw_ref=raw_ref, snippet="")

        m = NGINX_LOG_RE.match(line)
        if not m:
            return Unparsed(reason="unmatched_nginx_format", raw_ref=raw_ref, snippet=snippet)

        raw_ip = m.group("ip")
        ip = validate_ip(raw_ip)
        if not ip:
            return Unparsed(reason="bad_ip", raw_ref=raw_ref, snippet=snippet)

        # Parse timestamp
        ts_str = m.group("ts")
        ts = self._parse_nginx_timestamp(ts_str)
        if not ts:
            return Unparsed(reason="invalid_timestamp", raw_ref=raw_ref, snippet=snippet)

        # Parse request line: "GET /index.html HTTP/1.1" or malformed
        req_line = m.group("request")
        method: str | None = None
        path: str | None = None
        if req_line and req_line != "-":
            req_parts = req_line.split()
            if len(req_parts) >= 2:
                method = req_parts[0]
                path = req_parts[1]
            elif len(req_parts) == 1:
                path = req_parts[0]

        # Status & bytes
        status_val = int(m.group("status"))
        bytes_raw = m.group("bytes")
        bytes_val = int(bytes_raw) if bytes_raw.isdigit() else 0

        # Sanitize fields
        path_clean = clean_field(path, field_name="path")
        ua_raw = m.group("ua")
        ua_clean = clean_field(ua_raw if ua_raw != "-" else None, field_name="ua")
        user_raw = m.group("user")
        user_clean = clean_field(user_raw if user_raw != "-" else None, field_name="user")

        ev_id = Event.generate_id("nginx", ctx.file_path, line_no, ts)

        return Event(
            id=ev_id,
            ts=ts,
            source="nginx",
            kind="http_req",
            host=ctx.default_host,
            src_ip=ip,
            user=user_clean.cleaned if user_clean.cleaned else None,
            method=method,
            path=path_clean.cleaned if path_clean.cleaned else None,
            status=status_val,
            ua=ua_clean.cleaned if ua_clean.cleaned else None,
            bytes=bytes_val,
            truncated=(path_clean.truncated or ua_clean.truncated or user_clean.truncated),
            raw_ref=raw_ref,
        )

    @staticmethod
    def _parse_nginx_timestamp(ts_str: str) -> datetime | None:
        """Parse Nginx timestamp format '21/Oct/2026:03:14:01 +0000' to UTC datetime."""
        m = NGINX_TS_RE.match(ts_str)
        if not m:
            return None
        day_s, mon_s, yr_s, h_s, mi_s, s_s, tz_s = m.groups()
        month = MONTH_MAP.get(mon_s)
        if not month:
            return None

        # Build ISO string parseable by datetime.fromisoformat: '2026-10-21T03:14:01+00:00'
        tz_formatted = f"{tz_s[:3]}:{tz_s[3:]}"
        iso_str = f"{yr_s}-{month:02d}-{int(day_s):02d}T{h_s}:{mi_s}:{s_s}{tz_formatted}"
        try:
            dt = datetime.fromisoformat(iso_str)
            return dt.astimezone(UTC)
        except ValueError:
            return None
