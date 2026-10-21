"""Tests for multi-scale feature calculation and data leakage prevention."""

from datetime import UTC, datetime

from sloth_soc.features import (
    build_ip_day_features,
    compute_max_in_window,
    features_to_dataframe,
    shannon_entropy,
)
from sloth_soc.schema import Event, RawRef


def test_shannon_entropy():
    # Identical elements have 0 entropy
    assert shannon_entropy(["admin", "admin", "admin"]) == 0.0
    # Diverse elements have positive entropy
    assert shannon_entropy(["root", "admin", "test", "user"]) > 1.5


def test_compute_max_in_window():
    ts = [10.0, 20.0, 30.0, 500.0, 510.0]
    # In a 300s window, timestamps 10, 20, 30 are within window (size 3)
    assert compute_max_in_window(ts, 300.0) == 3


def test_feature_extraction_and_no_leakage():
    t1 = datetime(2026, 10, 21, 3, 12, 0, tzinfo=UTC)
    t2 = datetime(2026, 10, 21, 3, 14, 0, tzinfo=UTC)
    raw_ref = RawRef(file="auth.log", line_no=1)

    ev1 = Event(
        id="a1",
        ts=t1,
        source="sshd",
        kind="auth_fail",
        host="lab-vps",
        src_ip="203.0.113.5",
        user="root",
        raw_ref=raw_ref,
    )
    ev2 = Event(
        id="a2",
        ts=t2,
        source="sshd",
        kind="auth_fail",
        host="lab-vps",
        src_ip="203.0.113.5",
        user="admin",
        invalid_user=True,
        raw_ref=raw_ref,
    )

    rows = build_ip_day_features([ev1, ev2])
    assert len(rows) == 1
    row = rows[0]

    assert row.src_ip == "203.0.113.5"
    assert row.auth_fail_total == 2
    assert row.distinct_users == 2
    assert row.invalid_user_ratio == 0.5

    df = features_to_dataframe(rows)
    assert len(df) == 1

    # CRITICAL TEST: Verify no label or scenario columns reach the ML features
    ml_dict = row.to_ml_dict()
    forbidden_keys = {"src_ip", "day", "label", "scenario", "truth_severity"}
    for key in forbidden_keys:
        assert key not in ml_dict, f"Data leakage detected! {key} is present in ML features!"

    for key, val in ml_dict.items():
        assert isinstance(val, (int, float)), f"Non-numeric value in ML feature {key}: {val}"
