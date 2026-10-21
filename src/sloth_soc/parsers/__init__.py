"""Parser registry and file ingestion pipeline."""

from __future__ import annotations

import gzip
from pathlib import Path
from typing import TextIO

from sloth_soc.parsers.base import LogParser, ParserContext
from sloth_soc.parsers.fail2ban import Fail2banParser
from sloth_soc.parsers.nginx import NginxParser
from sloth_soc.parsers.sshd import SSHDParser
from sloth_soc.parsers.ufw import UFWParser
from sloth_soc.schema import Event, EventSource, ParseStats, Unparsed

PARSER_REGISTRY: dict[EventSource, LogParser] = {
    "sshd": SSHDParser(),
    "nginx": NginxParser(),
    "fail2ban": Fail2banParser(),
    "ufw": UFWParser(),
}


def get_parser(source: EventSource) -> LogParser:
    """Retrieve the parser instance for a given event source."""
    if source not in PARSER_REGISTRY:
        raise ValueError(f"Unknown log source: {source}")
    return PARSER_REGISTRY[source]


def parse_stream(
    stream: TextIO,
    source: EventSource,
    file_path: str = "stream",
    year_hint: int | None = None,
) -> tuple[list[Event], ParseStats]:
    """Parse a text stream of log lines into Events and ParseStats."""
    parser = get_parser(source)
    ctx = ParserContext(file_path=file_path, year_hint=year_hint)

    events: list[Event] = []
    stats = ParseStats()

    for line_no, raw_line in enumerate(stream, start=1):
        stats.lines_total += 1
        line = raw_line.rstrip("\r\n")

        res = parser.parse_line(line, line_no=line_no, ctx=ctx)
        if isinstance(res, Event):
            events.append(res)
            stats.parsed_total += 1
        elif isinstance(res, Unparsed):
            reason = res.reason
            stats.unparsed_by_reason[reason] = stats.unparsed_by_reason.get(reason, 0) + 1

    return events, stats


def parse_file(
    file_path: str | Path,
    source: EventSource,
    year_hint: int | None = None,
) -> tuple[list[Event], ParseStats]:
    """Parse a single file (plain text or gzipped) into Events and ParseStats."""
    path = Path(file_path)
    if not path.exists():
        return [], ParseStats()

    # Determine year hint from file mtime if not explicitly provided
    if year_hint is None:
        mtime = path.stat().st_mtime
        from datetime import UTC, datetime

        year_hint = datetime.fromtimestamp(mtime, UTC).year

    # Support .gz compression
    if path.suffix == ".gz":
        with gzip.open(path, mode="rt", encoding="utf-8", errors="replace") as f:
            return parse_stream(f, source=source, file_path=str(path), year_hint=year_hint)
    else:
        with open(path, encoding="utf-8", errors="replace") as f:
            return parse_stream(f, source=source, file_path=str(path), year_hint=year_hint)


__all__ = [
    "Fail2banParser",
    "LogParser",
    "NginxParser",
    "ParserContext",
    "SSHDParser",
    "UFWParser",
    "get_parser",
    "parse_file",
    "parse_stream",
]
