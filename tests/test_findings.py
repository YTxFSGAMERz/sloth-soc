"""Tests for findings generation, attention budget, and handled grouping."""

import pandas as pd

from sloth_soc.config import SlothSocConfig
from sloth_soc.detectors.rules import RuleDetector
from sloth_soc.findings import build_findings_from_df


def test_findings_budget_and_status():
    cfg = SlothSocConfig()
    cfg.detect.attention_budget = 2

    # Construct rows with different threat levels
    rows = [
        # Critical stuffing
        {"src_ip": "203.0.113.1", "day": "2026-10-21", "ok_after_fail": 1, "first_seen_ever": 1},
        # High exposed web probe
        {"src_ip": "203.0.113.2", "day": "2026-10-21", "probe_hits": 6, "probe_2xx": 1},
        # Medium burst
        {"src_ip": "203.0.113.3", "day": "2026-10-21", "auth_fail_max_5m": 20},
        # Blocked burst (handled while you slept)
        {
            "src_ip": "203.0.113.4",
            "day": "2026-10-21",
            "auth_fail_max_5m": 20,
            "banned": 1,
        },
        # Benign traffic
        {"src_ip": "198.51.100.5", "day": "2026-10-21", "http_total": 50},
    ]
    df = pd.DataFrame(rows)
    det = RuleDetector()

    attention, handled, status = build_findings_from_df(df, det, config=cfg)

    # 1. Overall status MUST be urgent due to critical finding
    assert status == "urgent"

    # 2. Attention budget limits to 2 findings
    assert len(attention) == 2
    # First finding must be the critical one
    assert attention[0].severity == "critical"
    assert attention[0].id == "F1"
    assert attention[0].entity == "203.0.113.1"

    # 3. Blocked item is in handled
    assert any(h.entity == "203.0.113.4" for h in handled)
    assert any(h.blocked for h in handled)


def test_quiet_status_for_benign_traffic():
    df = pd.DataFrame(
        [
            {"src_ip": "198.51.100.10", "day": "2026-10-21", "http_total": 20},
        ]
    )
    det = RuleDetector()
    attention, handled, status = build_findings_from_df(df, det)
    assert status == "quiet"
    assert len(attention) == 0
