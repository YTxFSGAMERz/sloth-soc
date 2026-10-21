"""Integration tests for sloth-soc demo and pipeline execution."""

from __future__ import annotations

from pathlib import Path

from sloth_soc.pipeline import run_synthetic_demo


def test_synthetic_demo_no_llm(tmp_path: Path):
    out_dir = tmp_path / "digests"
    synth_dir = tmp_path / "synthetic"

    res = run_synthetic_demo(
        seed=1,
        days=2,  # Quick 2-day run for fast unit test
        no_llm=True,
        out_dir=out_dir,
        synth_dir=synth_dir,
    )

    brief = res["brief"]
    narrator_out = res["narrator_output"]
    meta = res["metadata"]
    saved_files = res["saved_files"]

    assert brief.status in ("urgent", "attention", "quiet")
    assert narrator_out.status_claim == brief.status
    assert meta.narrator == "template"
    assert len(saved_files) == 3

    # Check files exist on disk
    for fmt in ["markdown", "html", "json"]:
        f_path = saved_files[fmt]
        assert f_path.exists()
        assert f_path.stat().st_size > 0

    # Verify JSON content is valid
    import json

    data = json.loads(saved_files["json"].read_text(encoding="utf-8"))
    assert "brief" in data
    assert "narrator_output" in data
    assert "metadata" in data
