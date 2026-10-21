"""Base classes and utility functions for log parsers."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sloth_soc.schema import Event, Unparsed

# Month name lookup for syslog formats
MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2})\s+([0-9]{1,2})\s+([0-9]{2}):([0-9]{2}):([0-9]{2})")
ISO_TS_RE = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}[T\s][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)"
)


@dataclass
class ParserContext:
    """Contextual metadata passed to parse_line."""

    file_path: str = "unknown"
    year_hint: int | None = None
    default_host: str = "localhost"


class LogParser(Protocol):
    """Protocol satisfied by all Sloth SOC log parsers."""

    def parse_line(self, line: str, line_no: int, ctx: ParserContext) -> Event | Unparsed: ...


def validate_ip(ip_str: str | None) -> str | None:
    """Validate and normalize IPv4 / IPv6 addresses; strips interface scope."""
    if not ip_str:
        return None
    # Strip potential interface scope e.g. fe80::1%eth0
    clean_str = ip_str.split("%")[0].strip()
    try:
        ip = ipaddress.ip_address(clean_str)
        return str(ip)
    except ValueError:
        return None


def parse_timestamp(
    ts_str: str,
    year_hint: int | None = None,
    now_ref: datetime | None = None,
) -> datetime | None:
    """Parse syslog or ISO-8601 timestamps into timezone-aware UTC datetime.

    Handles syslog year rollover: if parsed time is > 7 days ahead of reference,
    subtracts one year (e.g. reading December logs in January).
    """
    ts_str = ts_str.strip()
    ref_now = now_ref or datetime.now(UTC)
    current_year = year_hint or ref_now.year

    # 1. Try ISO-8601 / RFC 3339
    iso_match = ISO_TS_RE.match(ts_str)
    if iso_match:
        val = iso_match.group(1).replace(",", ".").replace(" ", "T")
        try:
            dt = datetime.fromisoformat(val)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)
        except ValueError:
            pass

    # 2. Try classic Syslog: "Oct 21 03:12:45"
    syslog_match = SYSLOG_TS_RE.match(ts_str)
    if syslog_match:
        mon_str, day_str, h_str, m_str, s_str = syslog_match.groups()
        month = MONTH_MAP.get(mon_str)
        if not month:
            return None
        day = int(day_str)
        hour, minute, second = int(h_str), int(m_str), int(s_str)

        try:
            dt = datetime(current_year, month, day, hour, minute, second, tzinfo=UTC)
        except ValueError:
            return None

        # Year rollover check: if more than 7 days in future compared to ref_now
        if (dt - ref_now).total_seconds() > 7 * 86400:
            dt = datetime(current_year - 1, month, day, hour, minute, second, tzinfo=UTC)

        return dt

    return None
