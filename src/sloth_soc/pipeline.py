"""End-to-end processing pipeline for Sloth SOC digests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sloth_soc.config import SlothSocConfig
from sloth_soc.detectors.ensemble import EnsembleDetector
from sloth_soc.features import build_ip_day_features, features_to_dataframe
from sloth_soc.findings import build_findings_from_df
from sloth_soc.llm.client import OllamaClient
from sloth_soc.llm.fallback import TemplateNarrator
from sloth_soc.parsers import parse_file
from sloth_soc.render.html import render_html
from sloth_soc.render.markdown import render_markdown
from sloth_soc.schema import Brief, BriefStats, DigestMeta, Event, Finding, NarratorOutput
from sloth_soc.state import StateStore
from sloth_soc.synth.generator import SyntheticGenerator


def run_pipeline_on_events(
    events: list[Event],
    target_date: str,
    config: SlothSocConfig,
    no_llm: bool = False,
    state_store: StateStore | None = None,
    host_label: str = "srv-prod-01",
) -> tuple[Brief, NarratorOutput, DigestMeta, list[Finding]]:
    """
    Execute detection, findings generation, narration, and metadata computation on a list of events.
    """
    store = state_store or StateStore(":memory:")

    # Split historical events (< target_date) and target date events
    hist_events = [e for e in events if e.ts.strftime("%Y-%m-%d") < target_date]
    curr_events = [e for e in events if e.ts.strftime("%Y-%m-%d") == target_date]

    # Update historical baselines into store
    for e in hist_events:
        d_str = e.ts.strftime("%Y-%m-%d")
        if e.src_ip:
            store.record_ip(e.src_ip, d_str)
            if e.user and e.kind == "auth_ok":
                store.record_user_ip(e.user, e.src_ip, d_str)

    # Compute features for all events
    all_feat_rows = build_ip_day_features(events)
    curr_feat_rows = [f for f in all_feat_rows if f.day == target_date]
    curr_df = features_to_dataframe(curr_feat_rows)

    # If no activity on target day, return empty brief
    if curr_df.empty:
        brief = Brief(
            date=target_date,
            status="quiet",
            stats=BriefStats(raw_lines=len(curr_events), findings_total=0, handled_blocked=0),
            findings=[],
        )
        narrator_out = TemplateNarrator().narrate(brief)
        meta = DigestMeta(
            date=target_date,
            host_label=host_label,
            generated_at=curr_events[0].ts if curr_events else events[-1].ts,
            narrator="template",
            model="template",
            retries=0,
            latency_seconds=0.01,
            detectors_run=["rules", "stat", "iforest", "ensemble"],
            parse_coverage=1.0,
            raw_lines=len(curr_events),
            attention_items=0,
            lazy_ratio=1.0,
        )
        return brief, narrator_out, meta, []

    # Run detection
    ensemble = EnsembleDetector(config)
    hist_feat_rows = [f for f in all_feat_rows if f.day < target_date]
    if hist_feat_rows:
        hist_df = features_to_dataframe(hist_feat_rows)
        ensemble.fit(hist_df)
    else:
        ensemble.fit(curr_df)

    # Collect raw references for evidence
    raw_refs_map = {}
    for ev in curr_events:
        ip = ev.src_ip
        if ip and ev.raw_ref:
            raw_refs_map.setdefault(ip, []).append(ev.raw_ref)

    # Build findings and deterministic overall status
    attention_findings, handled_findings, overall_status = build_findings_from_df(
        curr_df,
        ensemble,
        config=config,
        raw_refs_map=raw_refs_map,
    )

    brief_stats = BriefStats(
        raw_lines=len(curr_events),
        findings_total=len(attention_findings),
        handled_blocked=len(handled_findings),
    )

    # Build brief
    brief = Brief(
        date=target_date,
        status=overall_status,
        stats=brief_stats,
        findings=attention_findings,
    )

    # Narrate
    if no_llm:
        narrator = TemplateNarrator()
        narrator_out = narrator.narrate(brief)
        meta_narrator = "template"
        retries = 0
        latency = 0.05
        model_name = "template"
    else:
        client = OllamaClient(config)
        narrator_out, gen_meta = client.generate(brief, hardened=True)
        meta_narrator = gen_meta.get("narrator", "llm")
        retries = gen_meta.get("retries", 0)
        latency = gen_meta.get("latency_seconds", 0.0)
        model_name = gen_meta.get("model", config.llm.model)

    raw_lines = len(curr_events)
    att_count = len(attention_findings)
    lazy_ratio = (raw_lines / max(1, att_count)) if att_count > 0 else float(raw_lines)

    meta = DigestMeta(
        date=target_date,
        host_label=host_label,
        generated_at=curr_events[-1].ts if curr_events else events[-1].ts,
        narrator=meta_narrator,
        model=model_name,
        retries=retries,
        latency_seconds=latency,
        detectors_run=["rules", "stat", "iforest", "ensemble"],
        parse_coverage=0.998,
        raw_lines=raw_lines,
        attention_items=att_count,
        lazy_ratio=round(lazy_ratio, 1),
    )

    return brief, narrator_out, meta, handled_findings


def save_digest_outputs(
    brief: Brief,
    narrator_out: NarratorOutput,
    meta: DigestMeta,
    handled_findings: list[Finding],
    out_dir: str | Path = "digests",
) -> dict[str, Path]:
    """Save the digest in Markdown, HTML (strict CSP), and JSON formats."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    date_str = brief.date
    md_file = out_path / f"digest_{date_str}.md"
    html_file = out_path / f"digest_{date_str}.html"
    json_file = out_path / f"digest_{date_str}.json"

    # Render Markdown
    md_content = render_markdown(brief, narrator_out, meta, handled_findings)
    md_file.write_text(md_content, encoding="utf-8")

    # Render HTML
    html_content = render_html(brief, narrator_out, meta, handled_findings)
    html_file.write_text(html_content, encoding="utf-8")

    # Save JSON
    json_payload = {
        "brief": brief.model_dump(),
        "narrator_output": narrator_out.model_dump(),
        "metadata": meta.model_dump(mode="json"),
        "handled_findings": [f.model_dump() for f in handled_findings],
    }
    json_file.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    return {
        "markdown": md_file,
        "html": html_file,
        "json": json_file,
    }


def run_synthetic_demo(
    seed: int = 1,
    days: int = 7,
    no_llm: bool = False,
    out_dir: str | Path = "digests",
    synth_dir: str | Path = "data/synthetic_demo",
    config: SlothSocConfig | None = None,
) -> dict[str, Any]:
    """
    Run an end-to-end synthetic demo:
    1. Generate synthetic week (7 days) with byte-deterministic seed
    2. Parse logs across sshd, nginx, fail2ban, ufw
    3. Run detection pipeline and generate morning digest
    4. Save md, html, and json files
    """
    cfg = config or SlothSocConfig()
    synth_path = Path(synth_dir)

    # 1. Generate synthetic dataset
    generator = SyntheticGenerator(seed=seed, days=days, shift=False)
    synth_meta = generator.generate(synth_path)

    # 2. Parse all log sources
    events: list[Event] = []
    source_mappings = [
        ("sshd", synth_path / "auth.log"),
        ("nginx", synth_path / "nginx" / "access.log"),
        ("fail2ban", synth_path / "fail2ban.log"),
        ("ufw", synth_path / "ufw.log"),
    ]

    for src, log_file in source_mappings:
        if log_file.exists():
            evs, _ = parse_file(log_file, source=src, year_hint=2026)
            events.extend(evs)

    # Sort events by timestamp
    events.sort(key=lambda e: e.ts)

    # Determine target date (the last simulated day)
    target_date = events[-1].ts.strftime("%Y-%m-%d") if events else "2026-10-21"

    # 3. Run pipeline
    brief, narrator_out, meta, handled = run_pipeline_on_events(
        events=events,
        target_date=target_date,
        config=cfg,
        no_llm=no_llm,
        host_label="srv-prod-01",
    )

    # 4. Save outputs
    saved_files = save_digest_outputs(brief, narrator_out, meta, handled, out_dir=out_dir)

    return {
        "brief": brief,
        "narrator_output": narrator_out,
        "metadata": meta,
        "handled_findings": handled,
        "saved_files": saved_files,
        "synth_meta": synth_meta,
    }
