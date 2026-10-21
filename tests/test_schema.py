"""Tests for schema data contracts and feature leakage prevention."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sloth_soc.schema import (
    Brief,
    BriefStats,
    DigestItem,
    Event,
    FeatureRow,
    Finding,
    NarratorOutput,
    ParseStats,
    RawRef,
)


def test_event_creation_and_deterministic_id():
    now = datetime(2026, 10, 21, 3, 12, 45, tzinfo=UTC)
    raw_ref = RawRef(file="auth.log", line_no=123)
    ev_id = Event.generate_id("sshd", "auth.log", 123, now)

    event = Event(
        id=ev_id,
        ts=now,
        source="sshd",
        kind="auth_fail",
        host="lab-vps",
        src_ip="203.0.113.5",
        user="admin",
        raw_ref=raw_ref,
    )

    assert event.id == ev_id
    assert len(event.id) == 12
    assert event.source == "sshd"
    assert event.kind == "auth_fail"
    assert event.ts.tzinfo == UTC


def test_parse_stats_coverage():
    stats = ParseStats(lines_total=100, parsed_total=95, unparsed_by_reason={"bad_ip": 5})
    assert stats.coverage == 0.95

    empty_stats = ParseStats()
    assert empty_stats.coverage == 1.0


def test_feature_row_to_ml_dict_no_leakage():
    row = FeatureRow(
        src_ip="203.0.113.5",
        day="2026-10-21",
        auth_fail_total=35,
        auth_fail_max_5m=12,
        distinct_users=1,
        invalid_user_ratio=1.0,
        probe_hits=5,
    )

    ml_dict = row.to_ml_dict()

    # Must contain numeric values
    assert ml_dict["auth_fail_total"] == 35.0
    assert ml_dict["auth_fail_max_5m"] == 12.0
    assert ml_dict["probe_hits"] == 5.0

    # Non-negotiable: MUST NOT leak IP, day, labels, or scenario names into ML features
    forbidden_keys = {"src_ip", "day", "label", "scenario", "truth_severity"}
    for k in forbidden_keys:
        assert k not in ml_dict, f"Feature leakage detected: {k} in ML features!"


def test_finding_and_brief_creation():
    raw_ref = RawRef(file="auth.log", line_no=42)
    finding = Finding(
        id="F1",
        severity="critical",
        kind="ssh_success_after_failures",
        entity="203.0.113.9",
        window="03:12-03:19 UTC",
        reasons=["R5", "iforest_top_1pct"],
        evidence_refs=[raw_ref],
        action="CONFIRM_LEGIT_LOGIN",
    )

    brief = Brief(
        date="2026-10-21",
        status="urgent",
        stats=BriefStats(raw_lines=48213, findings_total=1, handled_blocked=0),
        findings=[finding],
    )

    assert brief.status == "urgent"
    assert len(brief.findings) == 1
    assert brief.findings[0].id == "F1"


def test_narrator_output_schema_validation():
    # Valid output
    valid_output = NarratorOutput(
        status_claim="urgent",
        tldr="One SSH login succeeded after multiple failed attempts. Investigate Alice's account.",
        items=[
            DigestItem(
                finding_id="F1",
                explanation="Address 203.0.113.9 succeeded after 37 failures.",
                action="CONFIRM_LEGIT_LOGIN",
            )
        ],
    )
    assert valid_output.status_claim == "urgent"

    # Invalid action enum rejected
    with pytest.raises(ValidationError):
        NarratorOutput(
            status_claim="urgent",
            tldr="Test",
            items=[
                DigestItem(
                    finding_id="F1",
                    explanation="Test",
                    action="RUN_ARBITRARY_COMMAND",  # type: ignore
                )
            ],
        )

    # Invalid finding_id pattern rejected
    with pytest.raises(ValidationError):
        DigestItem(
            finding_id="INVALID_ID",
            explanation="Test",
            action="CONFIRM_LEGIT_LOGIN",
        )
