"""Markdown digest renderer."""

from __future__ import annotations

from sloth_soc.schema import ACTION_TEXT_MAP, Brief, DigestMeta, Finding, NarratorOutput


def render_markdown(
    brief: Brief,
    narrator_out: NarratorOutput,
    meta: DigestMeta,
    handled_findings: list[Finding] | None = None,
) -> str:
    """Render the daily digest into formatted Markdown."""
    lines: list[str] = []

    status_tag = brief.status.upper()
    lines.append(f"# Sloth SOC Digest: {brief.date} (`{meta.host_label}`) — STATUS: {status_tag}")
    lines.append("")
    lines.append(f"**TL;DR:** {narrator_out.tldr}")
    lines.append("")

    # Map finding explanations from narrator output
    narrator_map = {item.finding_id: item for item in narrator_out.items}

    # Needs attention section
    attention_count = len(brief.findings)
    lines.append(f"## NEEDS YOUR ATTENTION ({attention_count})")
    lines.append("")

    if not brief.findings:
        lines.append("No active security threats requiring administrative attention.")
        lines.append("")
    else:
        for f in brief.findings:
            item = narrator_map.get(f.id)
            explanation = item.explanation if item else f.reasons[0]
            action_code = item.action if item else f.action
            action_text = ACTION_TEXT_MAP.get(action_code, action_code)

            lines.append(
                f"### {f.id}. [{f.severity.upper()}] `{f.entity}` — {f.kind.replace('_', ' ').title()}"
            )
            lines.append(f"- **Window:** {f.window}")
            lines.append(f"- **Analysis:** {explanation}")
            lines.append(f"- **Recommended Action:** {action_text}")

            refs_str = " | ".join(f"{r.file}:{r.line_no}" for r in f.evidence_refs[:5])
            if refs_str:
                lines.append(f"- **Evidence:** {refs_str}")
            lines.append("")

    # Handled while you slept
    handled_count = len(handled_findings or [])
    lines.append(f"## HANDLED WHILE YOU SLEPT ({handled_count})")
    lines.append("")
    if handled_findings:
        lines.append(
            f"{handled_count} suspicious source addresses were automatically blocked or dropped by edge rules."
        )
        for h in handled_findings[:5]:
            lines.append(f"- `{h.entity}`: {h.kind.replace('_', ' ')} (blocked)")
    else:
        lines.append("No automated blocks triggered overnight.")
    lines.append("")

    # Noise note
    lines.append("## NOISE IGNORED")
    lines.append("")
    lines.append(narrator_out.noise_note or "Normal background web crawlers and routine queries.")
    lines.append("")

    # Footer
    det_str = " ".join(meta.detectors_run) if meta.detectors_run else "rules ensemble"
    lines.append("---")
    lines.append(
        f"**Footer:** {meta.raw_lines:,} lines -> {meta.attention_items} items to read "
        f"(lazy ratio {meta.lazy_ratio:.0f}:1) | `{meta.model or 'template'}` | "
        f"narrator={meta.narrator} retries={meta.retries} latency={meta.latency_seconds:.1f}s | "
        f"detectors: {det_str} | parse coverage {meta.parse_coverage * 100:.1f}%"
    )
    lines.append("")

    return "\n".join(lines)
