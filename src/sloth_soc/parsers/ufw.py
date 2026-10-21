"""UFW (Uncomplicated Firewall) kernel log parser."""

from __future__ import annotations

import re

from sloth_soc.parsers.base import ParserContext, parse_timestamp, validate_ip
from sloth_soc.sanitize import clean_field
from sloth_soc.schema import Event, RawRef, Unparsed

# Prefix matching timestamp, host, and kernel [UFW ...] marker
UFW_PREFIX_RE = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})|"
    r"(?:[0-9]{4}-[0-9]{2}-[0-9]{2}[T\s][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?))\s+"
    r"(?P<host>[^\s:]+)\s+"
    r"(?:kernel:\s+(?:\[\s*[0-9]+(?:\.[0-9]+)?\]\s+)?)?"
    r"\[UFW\s+(?P<action>[A-Z]+)\]\s+"
    r"(?P<kv>.*)$"
)

# Key-value extractor: KEY=VALUE
KV_RE = re.compile(r"([A-Z_]+)=(\S*)")


class UFWParser:
    """Parser for UFW firewall log entries."""

    def parse_line(self, line: str, line_no: int, ctx: ParserContext) -> Event | Unparsed:
        line = line.replace("\r", "").replace("\n", "")
        raw_ref = RawRef(file=ctx.file_path, line_no=line_no)
        snippet = line[:80].strip()

        if not line.strip():
            return Unparsed(reason="empty_line", raw_ref=raw_ref, snippet="")

        m = UFW_PREFIX_RE.search(line)
        if not m:
            return Unparsed(reason="unmatched_ufw_format", raw_ref=raw_ref, snippet=snippet)

        ts_raw = m.group("ts")
        host_raw = m.group("host")
        action = m.group("action")
        kv_str = m.group("kv")

        ts = parse_timestamp(ts_raw, year_hint=ctx.year_hint)
        if not ts:
            return Unparsed(reason="invalid_timestamp", raw_ref=raw_ref, snippet=snippet)

        # Parse key=value pairs into dictionary
        kvs = dict(KV_RE.findall(kv_str))
        src_ip_raw = kvs.get("SRC")
        ip = validate_ip(src_ip_raw)
        if not ip:
            return Unparsed(reason="bad_ip", raw_ref=raw_ref, snippet=snippet)

        dpt_raw = kvs.get("DPT")
        port = int(dpt_raw) if dpt_raw and dpt_raw.isdigit() else None
        proto = kvs.get("PROTO")

        host_clean = clean_field(host_raw, field_name="host").cleaned or ctx.default_host
        ev_id = Event.generate_id("ufw", ctx.file_path, line_no, ts)

        # UFW BLOCK is fw_block; AUDIT can also be tracked
        kind = "fw_block" if action == "BLOCK" else "fw_block"

        return Event(
            id=ev_id,
            ts=ts,
            source="ufw",
            kind=kind,
            host=host_clean,
            src_ip=ip,
            port=port,
            method=proto,
            raw_ref=raw_ref,
        )
