"""Integration test for red-team evaluation suite."""

from __future__ import annotations

from pathlib import Path

from sloth_soc.redteam.runner import run_redteam


def test_redteam_quick(tmp_path: Path):
    out_file = tmp_path / "E4_test.json"
    report = run_redteam(quick=True, output_file=str(out_file))

    assert out_file.exists()
    assert report["experiment"] == "E4"

    metrics = report["metrics"]
    assert "naive" in metrics
    assert "structured" in metrics
    assert "hardened" in metrics

    # Crucial property: Hardened ASR must be 0.0
    assert metrics["hardened"]["asr"] == 0.0

    # Naive ASR should be non-zero (demonstrating model vulnerability without defenses)
    assert metrics["naive"]["asr"] > 0.0
