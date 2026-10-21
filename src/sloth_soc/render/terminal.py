"""Rich terminal output renderer for Sloth SOC digests."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sloth_soc.sanitize import clean_field
from sloth_soc.schema import ACTION_TEXT_MAP, Brief, DigestMeta, Finding, NarratorOutput


def print_terminal_digest(
    brief: Brief,
    narrator_out: NarratorOutput,
    meta: DigestMeta,
    handled_findings: list[Finding] | None = None,
    console: Console | None = None,
) -> None:
    """Print the daily security digest to the terminal using Rich."""
    c = console or Console()

    # Status color mapping
    status_style = {
        "urgent": "bold white on red",
        "attention": "bold black on yellow",
        "quiet": "bold white on green",
    }.get(brief.status, "bold white")

    # Header Panel
    header_text = (
        f"[bold]Sloth SOC Digest[/bold] — {brief.date} (host: {meta.host_label})    "
        f"[{status_style}] STATUS: {brief.status.upper()} [/{status_style}]\n\n"
        f"[cyan]TL;DR:[/cyan] {clean_field(narrator_out.tldr).cleaned}"
    )
    c.print(Panel(header_text, border_style="cyan"))

    # Attention Table
    if brief.findings:
        table = Table(
            title=f"NEEDS YOUR ATTENTION ({len(brief.findings)})",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("ID", width=4)
        table.add_column("Sev", width=8)
        table.add_column("Entity", style="cyan", width=18)
        table.add_column("Analysis & Action")

        narrator_map = {item.finding_id: item for item in narrator_out.items}

        for f in brief.findings:
            item = narrator_map.get(f.id)
            exp = item.explanation if item else f.reasons[0]
            clean_exp = clean_field(exp).cleaned
            act_code = item.action if item else f.action
            act_text = ACTION_TEXT_MAP.get(act_code, act_code)

            sev_color = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }.get(f.severity, "dim")

            content = f"{clean_exp}\n[bold dim]Action:[/bold dim] [italic]{act_text}[/italic]"
            table.add_row(
                f.id, f"[{sev_color}]{f.severity.upper()}[/{sev_color}]", f.entity, content
            )

        c.print(table)
    else:
        c.print("[dim green]No items require administrative attention today.[/dim green]")

    # Handled count
    handled_count = len(handled_findings or [])
    c.print(
        f"\n[bold green]HANDLED WHILE YOU SLEPT:[/bold green] {handled_count} source addresses automatically blocked/dropped."
    )

    # Footer
    footer_text = (
        f"[dim]Footer: {meta.raw_lines:,} lines -> {meta.attention_items} items to read "
        f"(lazy ratio {meta.lazy_ratio:.0f}:1) | {meta.model or 'template'} | "
        f"narrator={meta.narrator} retries={meta.retries} latency={meta.latency_seconds:.1f}s | "
        f"parse coverage {meta.parse_coverage * 100:.1f}%[/dim]\n"
    )
    c.print(footer_text)
