"""Deterministic security rule engine (Rules R1 - R8)."""

from __future__ import annotations

import numpy as np
import pandas as pd

from sloth_soc.config import RulesConfig
from sloth_soc.detectors.base import RuleMatch

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _safe_int(val: object, default: int = 0) -> int:
    if val is None or pd.isna(val):
        return default
    try:
        return int(val)  # type: ignore
    except (ValueError, TypeError):
        return default


def _safe_float(val: object, default: float = 0.0) -> float:
    if val is None or pd.isna(val):
        return default
    try:
        return float(val)  # type: ignore
    except (ValueError, TypeError):
        return default


def evaluate_rules(row: pd.Series, cfg: RulesConfig | None = None) -> list[RuleMatch]:
    """Evaluate deterministic rules R1 through R8 against a single feature row."""
    c = cfg or RulesConfig()
    matches: list[RuleMatch] = []

    # R1: Brute-force burst
    fail_max_5m = _safe_int(row.get("auth_fail_max_5m"))
    if fail_max_5m >= c.r1_fail_5m:
        matches.append(
            RuleMatch(
                rule_id="R1",
                severity="medium",
                kind="ssh_brute_force_burst",
                reason=f"Brute-force burst: {fail_max_5m} failures in 5 minutes (threshold >= {c.r1_fail_5m})",
            )
        )

    # R2: Username spray
    dist_users = _safe_int(row.get("distinct_users"))
    inv_ratio = _safe_float(row.get("invalid_user_ratio"))
    if dist_users >= c.r2_users and inv_ratio >= 0.6:
        matches.append(
            RuleMatch(
                rule_id="R2",
                severity="medium",
                kind="ssh_user_spray",
                reason=f"Username spray: {dist_users} users probed ({inv_ratio * 100:.0f}% invalid users)",
            )
        )

    # R3: Web probing
    probe_hits = _safe_int(row.get("probe_hits"))
    probe_2xx = _safe_int(row.get("probe_2xx"))
    if probe_hits >= c.r3_probes:
        if probe_2xx >= 1:
            matches.append(
                RuleMatch(
                    rule_id="R3b",
                    severity="high",
                    kind="web_probe_exposed_path",
                    reason=f"Web probing: {probe_hits} probe hits, and {probe_2xx} sensitive path(s) returned HTTP 200!",
                )
            )
        else:
            matches.append(
                RuleMatch(
                    rule_id="R3",
                    severity="medium",
                    kind="web_path_probing",
                    reason=f"Web probing: {probe_hits} hits on sensitive endpoints (all error status)",
                )
            )

    # R4: Port scan
    max_ports_5m = _safe_int(row.get("max_ports_5m"))
    if max_ports_5m >= c.r4_ports:
        matches.append(
            RuleMatch(
                rule_id="R4",
                severity="medium",
                kind="port_scan",
                reason=f"Port scan: {max_ports_5m} destination ports probed in 5 minutes",
            )
        )

    # R5: Credential stuffing / success after failure (CRITICAL)
    ok_after_fail = _safe_int(row.get("ok_after_fail"))
    first_seen_ever = _safe_int(row.get("first_seen_ever"), default=1)
    if ok_after_fail == 1 and first_seen_ever == 1:
        matches.append(
            RuleMatch(
                rule_id="R5",
                severity="critical",
                kind="ssh_success_after_failures",
                reason="CRITICAL: SSH login success following >= 10 failed attempts from an unknown host",
            )
        )

    # R6: Known user from new source
    new_source_for_user = _safe_int(row.get("new_source_for_user"))
    auth_ok_total = _safe_int(row.get("auth_ok_total"))
    if new_source_for_user == 1 and auth_ok_total >= 1 and ok_after_fail == 0:
        matches.append(
            RuleMatch(
                rule_id="R6",
                severity="low",
                kind="new_source_for_user",
                reason="Authorized user authenticated from a previously unseen IP address (travel / new device)",
            )
        )

    # R7: Low-and-slow brute force
    fail_total = _safe_int(row.get("auth_fail_total"))
    active_hours = _safe_int(row.get("active_hours"))
    if fail_total >= 8 and active_hours >= 6 and fail_max_5m < c.r1_fail_5m:
        matches.append(
            RuleMatch(
                rule_id="R7",
                severity="medium",
                kind="low_and_slow_ssh",
                reason=f"Low-and-slow SSH probing: {fail_total} attempts spread across {active_hours} hours without burst",
            )
        )

    # R8: Prompt injection or hostile string detected
    inj_hits = _safe_int(row.get("inj_marker_hits"))
    if inj_hits >= 1:
        matches.append(
            RuleMatch(
                rule_id="R8",
                severity="medium",
                kind="prompt_injection_attempt",
                reason=f"Hostile injection pattern: {inj_hits} prompt-injection or exploit markers in untrusted fields",
            )
        )

    return matches


class RuleDetector:
    """Detector wrapping rule evaluations."""

    def __init__(self, config: RulesConfig | None = None) -> None:
        self.config = config or RulesConfig()

    def fit(self, X: pd.DataFrame, y: pd.Series | None = None) -> None:
        """Rules are deterministic and require no training."""
        pass

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Score based on highest severity rule match."""
        scores = np.zeros(len(X), dtype=float)
        for i, (_, row) in enumerate(X.iterrows()):
            matches = evaluate_rules(row, self.config)
            if not matches:
                scores[i] = 0.0
            else:
                max_sev = max(matches, key=lambda m: SEVERITY_ORDER[m.severity]).severity
                scores[i] = (SEVERITY_ORDER[max_sev] + 1) / 5.0
        return scores

    def explain(self, row: pd.Series) -> list[str]:
        matches = evaluate_rules(row, self.config)
        return [f"[{m.rule_id}] {m.reason}" for m in matches]
