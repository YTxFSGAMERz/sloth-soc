"""Ranking, severity scoring, and attention budget filtering for security findings."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pandas as pd

from sloth_soc.config import SlothSocConfig
from sloth_soc.detectors.rules import SEVERITY_ORDER, evaluate_rules
from sloth_soc.schema import (
    ActionEnum,
    DigestStatus,
    Finding,
    FindingEvidence,
    FindingSeverity,
    RawRef,
)

if TYPE_CHECKING:
    from sloth_soc.detectors.base import Detector


ACTION_MAP: dict[str, ActionEnum] = {
    "ssh_success_after_failures": "CONFIRM_LEGIT_LOGIN",
    "web_probe_exposed_path": "REVIEW_WEB_LOGS",
    "web_path_probing": "REVIEW_WEB_LOGS",
    "ssh_brute_force_burst": "ENABLE_KEY_ONLY_AUTH",
    "ssh_user_spray": "REVIEW_AUTH_LOG",
    "port_scan": "BLOCK_IP_AT_FIREWALL",
    "low_and_slow_ssh": "REVIEW_AUTH_LOG",
    "new_source_for_user": "CONFIRM_LEGIT_LOGIN",
    "prompt_injection_attempt": "REVIEW_AUTH_LOG",
    "ml_anomaly": "REVIEW_AUTH_LOG",
}


def _safe_int(val: object, default: int = 0) -> int:
    if val is None or pd.isna(val):
        return default
    try:
        return int(val)  # type: ignore
    except (ValueError, TypeError):
        return default


def build_findings_from_df(
    df: pd.DataFrame,
    detector: Detector,
    config: SlothSocConfig | None = None,
    raw_refs_map: dict[str, list[RawRef]] | None = None,
) -> tuple[list[Finding], list[Finding], DigestStatus]:
    """Score feature rows and produce (attention_findings, handled_findings, overall_status).

    Enforces the attention budget and handled grouping.
    """
    cfg = config or SlothSocConfig()
    budget = cfg.detect.attention_budget
    raw_map = raw_refs_map or {}

    if df.empty:
        return [], [], "quiet"

    # Compute detector scores
    scores = detector.score(df)
    all_findings: list[Finding] = []

    for i, (_, row) in enumerate(df.iterrows()):
        ip = str(row.get("src_ip", "unknown"))
        day = str(row.get("day", ""))
        score = float(scores[i])

        # Evaluate rules
        matches = evaluate_rules(row, cfg.detect.rules)
        explanations = detector.explain(row)

        is_blocked = bool(row.get("banned", 0) == 1 or row.get("fw_block_total", 0) > 0)

        # Determine severity and kind
        severity: FindingSeverity = "info"
        kind = "benign_traffic"

        if matches:
            top_match = max(matches, key=lambda m: SEVERITY_ORDER[m.severity])
            severity = top_match.severity  # type: ignore
            kind = top_match.kind
        elif score >= 0.90:  # Top 10% statistical / ML anomaly
            severity = "medium"
            kind = "ml_anomaly"
        elif score >= 0.75:
            severity = "low"
            kind = "mild_anomaly"

        # Determine action
        action: ActionEnum = ACTION_MAP.get(kind, "NO_ACTION_MONITOR")

        evidence = FindingEvidence(
            counts={
                "auth_fail_total": _safe_int(row.get("auth_fail_total")),
                "auth_fail_max_5m": _safe_int(row.get("auth_fail_max_5m")),
                "probe_hits": _safe_int(row.get("probe_hits")),
                "http_total": _safe_int(row.get("http_total")),
                "fw_block_total": _safe_int(row.get("fw_block_total")),
            },
            blocked=is_blocked,
            failed_attempts=_safe_int(row.get("auth_fail_total")),
            distinct_users=_safe_int(row.get("distinct_users")),
        )

        refs = raw_map.get(ip, [])[:20]

        finding = Finding(
            id=f"F{i + 1}",
            severity=severity,
            kind=kind,
            entity=ip,
            window=f"{day} UTC",
            evidence=evidence,
            reasons=explanations if explanations else [kind],
            evidence_refs=refs,
            blocked=is_blocked,
            score=score,
            action=action,
        )
        all_findings.append(finding)

    # Partition into "Handled while you slept" vs "Needs attention"
    handled: list[Finding] = []
    attention: list[Finding] = []

    for f in all_findings:
        # Blocked and at most medium severity is considered handled
        if f.blocked and SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER["medium"]:
            handled.append(f)
        elif SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["low"]:
            attention.append(f)

    # Sort attention findings: Critical first, then by score descending
    attention.sort(
        key=lambda f: (SEVERITY_ORDER[f.severity], f.score),
        reverse=True,
    )

    # Number findings sequentially F1, F2, ...
    budgeted_attention: list[Finding] = []
    for idx, f in enumerate(attention[:budget], start=1):
        budgeted_attention.append(
            Finding(
                id=f"F{idx}",
                severity=f.severity,
                kind=f.kind,
                entity=f.entity,
                window=f.window,
                evidence=f.evidence,
                reasons=f.reasons,
                evidence_refs=f.evidence_refs,
                blocked=f.blocked,
                score=f.score,
                action=f.action,
            )
        )

    # Determine deterministic overall status
    has_critical = any(f.severity == "critical" for f in budgeted_attention)
    has_high_or_med = any(f.severity in ("high", "medium") for f in budgeted_attention)

    if has_critical:
        overall_status: DigestStatus = "urgent"
    elif has_high_or_med:
        overall_status = "attention"
    else:
        overall_status = "quiet"

    return budgeted_attention, handled, overall_status
