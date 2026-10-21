"""Multi-scale feature extraction for IP-day analysis units."""

from __future__ import annotations

import math
from collections import Counter
from typing import TYPE_CHECKING

import numpy as np
import pandas as pd

from sloth_soc.sanitize import detect_injection_markers
from sloth_soc.schema import Event, FeatureRow

if TYPE_CHECKING:
    from sloth_soc.state import StateStore

# Curated probe path list
SENSITIVE_PROBE_SUBSTRINGS = [
    ".env",
    ".git",
    "wp-login",
    "wp-admin",
    "phpmyadmin",
    "xmlrpc.php",
    "actuator",
    "credentials",
    "backup",
    "database.yml",
    "graphql",
    "swagger",
    "dump.tar",
]

SUSPICIOUS_UA_SUBSTRINGS = [
    "curl",
    "wget",
    "python",
    "nikto",
    "sqlmap",
    "nmap",
    "masscan",
    "zgrab",
    "go-http-client",
]


def shannon_entropy(items: list[str]) -> float:
    """Calculate Shannon entropy (bits) of a discrete collection."""
    if not items:
        return 0.0
    total = len(items)
    counts = Counter(items)
    ent = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def compute_max_in_window(timestamps: list[float], window_seconds: float = 300.0) -> int:
    """Compute maximum count of events in any sliding time window."""
    if not timestamps:
        return 0
    if len(timestamps) == 1:
        return 1

    sorted_ts = sorted(timestamps)
    max_count = 0
    left = 0

    for right in range(len(sorted_ts)):
        while sorted_ts[right] - sorted_ts[left] > window_seconds:
            left += 1
        max_count = max(max_count, right - left + 1)

    return max_count


def compute_max_ports_in_window(
    port_events: list[tuple[float, int]], window_seconds: float = 300.0
) -> int:
    """Compute maximum distinct ports in any sliding time window."""
    if not port_events:
        return 0
    sorted_ev = sorted(port_events, key=lambda x: x[0])
    max_distinct = 0
    left = 0

    for right in range(len(sorted_ev)):
        while sorted_ev[right][0] - sorted_ev[left][0] > window_seconds:
            left += 1
        current_ports = {p for _, p in sorted_ev[left : right + 1]}
        max_distinct = max(max_distinct, len(current_ports))

    return max_distinct


def build_ip_day_features(
    events: list[Event],
    state: StateStore | None = None,
) -> list[FeatureRow]:
    """Group events by (src_ip, UTC day) and compute multi-scale features."""
    if not events:
        return []

    # Partition events by (src_ip, day_str)
    groups: dict[tuple[str, str], list[Event]] = {}
    for ev in events:
        day_str = ev.ts.strftime("%Y-%m-%d")
        key = (ev.src_ip, day_str)
        groups.setdefault(key, []).append(ev)

    results: list[FeatureRow] = []

    for (ip, day_str), ev_list in groups.items():
        # Sort chronologically
        ev_list.sort(key=lambda x: x.ts)

        auth_fails: list[Event] = []
        auth_oks: list[Event] = []
        http_reqs: list[Event] = []
        fw_blocks: list[Event] = []
        bans: list[Event] = []
        all_timestamps: list[float] = []
        active_hours_set: set[int] = set()
        sources_set: set[str] = set()
        inj_hits = 0

        for ev in ev_list:
            t_sec = ev.ts.timestamp()
            all_timestamps.append(t_sec)
            active_hours_set.add(ev.ts.hour)
            sources_set.add(ev.source)

            # Check injection markers
            text_fields = [ev.user or "", ev.path or "", ev.ua or ""]
            for tf in text_fields:
                if tf:
                    inj_hits += detect_injection_markers(tf, had_control_chars=ev.truncated)

            if ev.kind == "auth_fail":
                auth_fails.append(ev)
            elif ev.kind == "auth_ok":
                auth_oks.append(ev)
            elif ev.kind == "http_req":
                http_reqs.append(ev)
            elif ev.kind == "fw_block":
                fw_blocks.append(ev)
            elif ev.kind == "ban":
                bans.append(ev)

        # 1. Auth features
        auth_fail_total = len(auth_fails)
        fail_timestamps = [ev.ts.timestamp() for ev in auth_fails]
        auth_fail_max_5m = compute_max_in_window(fail_timestamps, 300.0)

        attempted_users = [ev.user for ev in auth_fails if ev.user]
        distinct_users = len(set(attempted_users))
        user_entropy_val = shannon_entropy(attempted_users)
        invalid_count = sum(1 for ev in auth_fails if ev.invalid_user)
        invalid_ratio = (invalid_count / auth_fail_total) if auth_fail_total > 0 else 0.0

        auth_ok_total = len(auth_oks)

        # ok_after_fail: 1 if success follows >= 10 failures within 30 min (1800s)
        ok_after_fail = 0
        if auth_ok_total > 0 and auth_fail_total >= 10:
            for ok_ev in auth_oks:
                ok_time = ok_ev.ts.timestamp()
                prior_fails = sum(1 for t in fail_timestamps if 0 < (ok_time - t) <= 1800.0)
                if prior_fails >= 10:
                    ok_after_fail = 1
                    break

        # 2. Timing features
        iat_cv = 0.0
        if len(all_timestamps) >= 2:
            iats = np.diff(all_timestamps)
            mean_iat = np.mean(iats)
            std_iat = np.std(iats)
            if mean_iat > 0:
                iat_cv = float(std_iat / mean_iat)

        active_hours = len(active_hours_set)

        # 3. Web features
        http_total = len(http_reqs)
        http_4xx = sum(1 for ev in http_reqs if ev.status and 400 <= ev.status < 500)
        http_404 = sum(1 for ev in http_reqs if ev.status == 404)
        http_4xx_ratio = (http_4xx / http_total) if http_total > 0 else 0.0
        http_404_ratio = (http_404 / http_total) if http_total > 0 else 0.0

        paths = [ev.path for ev in http_reqs if ev.path]
        distinct_paths = len(set(paths))
        path_entropy_val = shannon_entropy(paths)

        probe_hits = 0
        probe_2xx = 0
        for ev in http_reqs:
            p_lower = (ev.path or "").lower()
            if any(sub in p_lower for sub in SENSITIVE_PROBE_SUBSTRINGS):
                probe_hits += 1
                if ev.status and 200 <= ev.status < 300:
                    probe_2xx += 1

        uas = [ev.ua for ev in http_reqs if ev.ua]
        ua_distinct = len(set(uas))
        ua_suspicious = 0
        for ev in http_reqs:
            ua_str = (ev.ua or "").lower()
            if not ua_str or any(sub in ua_str for sub in SUSPICIOUS_UA_SUBSTRINGS):
                ua_suspicious += 1

        # 4. Firewall features
        fw_block_total = len(fw_blocks)
        ports = [ev.port for ev in fw_blocks if ev.port is not None]
        distinct_dst_ports = len(set(ports))
        port_events = [(ev.ts.timestamp(), ev.port) for ev in fw_blocks if ev.port is not None]
        max_ports_5m = compute_max_ports_in_window(port_events, 300.0)

        # 5. Context features
        banned = 1 if len(bans) > 0 else 0
        sources_touched = len(sources_set)

        first_seen_ever = 1
        new_source_for_user = 0
        if state is not None:
            first_seen_ever = 0 if state.is_known_ip(ip) else 1
            for ok_ev in auth_oks:
                if ok_ev.user and not state.is_known_user_ip(ok_ev.user, ip):
                    new_source_for_user = 1
                    break

        row = FeatureRow(
            src_ip=ip,
            day=day_str,
            auth_fail_total=auth_fail_total,
            auth_fail_max_5m=auth_fail_max_5m,
            distinct_users=distinct_users,
            invalid_user_ratio=float(invalid_ratio),
            user_entropy=float(user_entropy_val),
            auth_ok_total=auth_ok_total,
            ok_after_fail=ok_after_fail,
            iat_cv=float(iat_cv),
            active_hours=active_hours,
            http_total=http_total,
            http_4xx_ratio=float(http_4xx_ratio),
            http_404_ratio=float(http_404_ratio),
            probe_hits=probe_hits,
            probe_2xx=probe_2xx,
            distinct_paths=distinct_paths,
            path_entropy=float(path_entropy_val),
            ua_suspicious=ua_suspicious,
            ua_distinct=ua_distinct,
            fw_block_total=fw_block_total,
            distinct_dst_ports=distinct_dst_ports,
            max_ports_5m=max_ports_5m,
            banned=banned,
            sources_touched=sources_touched,
            first_seen_ever=first_seen_ever,
            new_source_for_user=new_source_for_user,
            inj_marker_hits=inj_hits,
        )
        results.append(row)

    return results


def features_to_dataframe(feature_rows: list[FeatureRow]) -> pd.DataFrame:
    """Convert a list of FeatureRow instances into a pandas DataFrame."""
    if not feature_rows:
        cols = ["src_ip", "day"] + FeatureRow.ml_feature_names()
        return pd.DataFrame(columns=cols)

    data = [row.model_dump() for row in feature_rows]
    return pd.DataFrame(data)
