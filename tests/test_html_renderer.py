"""Unit tests for HTML digest renderer (CSP, autoescaping, external URL check)."""

from __future__ import annotations

import datetime

from sloth_soc.render.html import render_html
from sloth_soc.schema import (
    Brief,
    BriefStats,
    DigestItem,
    DigestMeta,
    Finding,
    FindingEvidence,
    NarratorOutput,
    RawRef,
)


def test_html_renderer_csp_header():
    brief = Brief(
        date="2026-10-21",
        status="urgent",
        stats=BriefStats(raw_lines=5000, findings_total=1, handled_blocked=2),
        findings=[
            Finding(
                id="F1",
                severity="critical",
                kind="credential_stuffing_burst",
                entity="198.51.100.22",
                window="03:00-03:05 UTC",
                evidence=FindingEvidence(counts={"auth_fail_total": 48}, blocked=False),
                reasons=["Rapid failed logins"],
                action="ROTATE_CREDENTIALS",
                evidence_refs=[RawRef(file="auth.log", line_no=120)],
            )
        ],
    )
    narrator_out = NarratorOutput(
        status_claim="urgent",
        tldr="Critical authentication brute-force detected.",
        items=[
            DigestItem(
                finding_id="F1",
                explanation="Observed 48 rapid failed attempts.",
                action="ROTATE_CREDENTIALS",
            )
        ],
    )
    meta = DigestMeta(
        date="2026-10-21",
        host_label="srv-prod-01",
        generated_at=datetime.datetime.now(datetime.UTC),
        narrator="template",
        model="template",
        retries=0,
        latency_seconds=0.05,
        detectors_run=["rules", "stat", "iforest"],
        parse_coverage=0.998,
        raw_lines=5000,
        attention_items=1,
        lazy_ratio=5000.0,
    )

    html = render_html(brief, narrator_out, meta, handled_findings=[])

    # 1. Assert CSP meta tag exists and is strict
    assert '<meta http-equiv="Content-Security-Policy"' in html
    assert "default-src 'none'" in html

    # 2. Assert no external URLs exist in the HTML body (no http:// or https:// outside meta)
    body_lines = [line for line in html.splitlines() if "Content-Security-Policy" not in line]
    body_text = "\n".join(body_lines)
    assert "http://" not in body_text
    assert "https://" not in body_text


def test_html_renderer_autoescapes_hostile_markup():
    # Inject XSS attempts in entity, explanation, and TL;DR
    brief = Brief(
        date="2026-10-21",
        status="urgent",
        stats=BriefStats(raw_lines=100, findings_total=1, handled_blocked=0),
        findings=[
            Finding(
                id="F1",
                severity="critical",
                kind="xss_attempt",
                entity="<script>alert(1)</script>",
                window="01:00 UTC",
                evidence=FindingEvidence(counts={}, blocked=False),
                reasons=['<img src="http://evil.invalid/x">'],
                action="ROTATE_CREDENTIALS",
            )
        ],
    )
    narrator_out = NarratorOutput(
        status_claim="urgent",
        tldr='Attack with <script>evil()</script> and <b onmouseover="alert()">hover</b>',
        items=[
            DigestItem(
                finding_id="F1",
                explanation='Malicious payload: <img src="x" onerror="evil()"/>',
                action="ROTATE_CREDENTIALS",
            )
        ],
    )
    meta = DigestMeta(
        date="2026-10-21",
        host_label="srv-test",
        generated_at=datetime.datetime.now(datetime.UTC),
        narrator="template",
        model="template",
        retries=0,
        latency_seconds=0.01,
        detectors_run=["rules"],
        parse_coverage=1.0,
        raw_lines=100,
        attention_items=1,
        lazy_ratio=100.0,
    )

    html = render_html(brief, narrator_out, meta, handled_findings=[])

    # Assert raw script and img tags are escaped
    assert "<script>" not in html
    assert "</script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
