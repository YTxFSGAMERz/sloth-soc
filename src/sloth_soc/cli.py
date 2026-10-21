"""Command Line Interface for Sloth SOC."""

from __future__ import annotations

import importlib.metadata
import os
import platform
import socket
import sys
from datetime import UTC

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sloth_soc.config import load_config

app = typer.Typer(
    name="sloth-soc",
    help="Sloth SOC: Offline lazy security analyst",
    no_args_is_help=True,
)
console = Console()


@app.command()
def doctor(
    config_path: str = typer.Option(None, "--config", "-c", help="Path to custom config.yaml"),
) -> None:
    """Check environment, dependencies, Ollama loopback, and model presence."""
    cfg = load_config(config_path)

    console.print(
        Panel.fit(
            "[bold green]Sloth SOC[/bold green] Environment & Health Diagnostics",
            border_style="cyan",
        )
    )

    table = Table(title="Diagnostic Checks", show_header=True, header_style="bold magenta")
    table.add_column("Component", style="cyan", width=22)
    table.add_column("Status", width=14)
    table.add_column("Details", style="dim")

    # 1. Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):  # noqa: UP036
        table.add_row("Python Version", "[green]OK[/green]", f"Python {py_ver}")
    else:
        table.add_row(
            "Python Version",
            "[red]FAIL[/red]",
            f"Python {py_ver} (Requires >= 3.11)",
        )

    # 2. Key Libraries
    key_pkgs = [
        "pydantic",
        "pandas",
        "scikit-learn",
        "scipy",
        "jinja2",
        "rich",
        "httpx",
        "pyyaml",
    ]
    missing_pkgs = []
    installed_pkgs = []
    for pkg in key_pkgs:
        try:
            ver = importlib.metadata.version(pkg)
            installed_pkgs.append(f"{pkg}=={ver}")
        except importlib.metadata.PackageNotFoundError:
            missing_pkgs.append(pkg)

    if not missing_pkgs:
        table.add_row(
            "Core Packages",
            "[green]OK[/green]",
            f"All {len(key_pkgs)} core packages installed",
        )
    else:
        table.add_row(
            "Core Packages",
            "[yellow]MISSING[/yellow]",
            f"Missing: {', '.join(missing_pkgs)}",
        )

    # 3. Ollama Reachability & Models
    ollama_status = "[red]UNREACHABLE[/red]"
    ollama_details = f"Cannot reach {cfg.llm.host}. Run 'ollama serve' or start Ollama."
    models_found: list[str] = []
    target_model_present = False

    try:
        resp = httpx.get(f"{cfg.llm.host}/api/tags", timeout=1.5)
        if resp.status_code == 200:
            ollama_status = "[green]ONLINE[/green]"
            tags_data = resp.json()
            models_found = [m.get("name", "") for m in tags_data.get("models", [])]
            target_model = cfg.llm.model
            target_model_present = any(target_model in m for m in models_found)
            ollama_details = f"Connected at {cfg.llm.host} ({len(models_found)} models installed)"
    except Exception:
        pass

    table.add_row("Ollama Service", ollama_status, ollama_details)

    if models_found:
        if target_model_present:
            table.add_row(
                "Configured Model",
                "[green]READY[/green]",
                f"Found '{cfg.llm.model}' in local tags",
            )
        else:
            table.add_row(
                "Configured Model",
                "[yellow]NOT PULLED[/yellow]",
                f"'{cfg.llm.model}' not in {models_found}. Pull with 'ollama pull {cfg.llm.model}'",
            )
    else:
        table.add_row(
            "Configured Model",
            "[dim]UNKNOWN[/dim]",
            f"Target: {cfg.llm.model} (Ollama not connected)",
        )

    # 4. TabPFN Availability
    try:
        import tabpfn  # noqa: F401

        table.add_row(
            "TabPFN (Optional)",
            "[green]AVAILABLE[/green]",
            "TabPFN package imported successfully",
        )
    except ImportError:
        table.add_row(
            "TabPFN (Optional)",
            "[dim]NOT INSTALLED[/dim]",
            "Optional: system falls back to IsolationForest & Rules",
        )

    # 5. Network / Offline Status
    # Verify local hostname resolution without remote external connection
    is_offline = False
    try:
        # Check if an external address can be reached or if socket fails
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.settimeout(0.5)
        # Attempt connection to a reserved test IP (RFC 5737 TEST-NET-1)
        test_sock.connect(("192.0.2.1", 80))
        test_sock.close()
    except OSError:
        is_offline = True

    net_info = "Network available (local dev mode)" if not is_offline else "Offline / isolated"
    table.add_row("Network Status", "[green]OK[/green]", net_info)

    # 6. Hardware & Platform Details
    hw_info = (
        f"OS: {platform.system()} {platform.release()} | "
        f"CPU Cores: {os.cpu_count() or 'N/A'} | "
        f"Arch: {platform.machine()}"
    )
    table.add_row("Hardware", "[cyan]INFO[/cyan]", hw_info)

    console.print(table)
    console.print("\n[bold]Next Actions:[/bold]")
    if ollama_status != "[green]ONLINE[/green]":
        console.print(
            " - Launch Ollama: start the desktop application or run [cyan]ollama serve[/cyan]"
        )
        console.print(
            f" - Pull model: [cyan]ollama pull {cfg.llm.model}[/cyan] (or [cyan]ollama pull gemma4:e2b[/cyan])"
        )
    elif not target_model_present:
        console.print(f" - Pull model: [cyan]ollama pull {cfg.llm.model}[/cyan]")
    console.print(
        " - Development can proceed immediately with [cyan]FakeLLM[/cyan] and [cyan]--no-llm[/cyan].\n"
    )


@app.command()
def demo(
    no_llm: bool = typer.Option(False, "--no-llm", help="Use deterministic template narrator"),
    seed: int = typer.Option(1, "--seed", help="Random seed for synthetic week"),
    out_dir: str = typer.Option("digests", "--out", help="Output directory for digests"),
) -> None:
    """Generate a synthetic week, run the full pipeline, and write a digest."""
    from sloth_soc.pipeline import run_synthetic_demo
    from sloth_soc.render.terminal import print_terminal_digest

    console.print(
        Panel.fit(
            f"[bold green]Sloth SOC Demo[/bold green] (seed={seed}, no_llm={no_llm})",
            border_style="cyan",
        )
    )

    with console.status(
        "[cyan]Running demo: generating synthetic week and executing detection pipeline...[/cyan]"
    ):
        res = run_synthetic_demo(seed=seed, no_llm=no_llm, out_dir=out_dir)

    brief = res["brief"]
    narrator_out = res["narrator_output"]
    meta = res["metadata"]
    handled = res["handled_findings"]
    saved_files = res["saved_files"]

    # Print terminal output
    print_terminal_digest(brief, narrator_out, meta, handled, console=console)

    console.print("[bold green]Digest files generated successfully:[/bold green]")
    for fmt, p in saved_files.items():
        console.print(f"  - [{fmt.upper()}] {p}")
    console.print()


@app.command()
def synth(
    seed: int = typer.Option(1, "--seed", help="Random seed"),
    days: int = typer.Option(7, "--days", help="Number of simulated days"),
    shift: bool = typer.Option(False, "--shift", help="Enable distribution shift"),
    out: str = typer.Option("data/synthetic", "--out", help="Output directory"),
) -> None:
    """Generate synthetic log files and ground-truth labels."""
    from sloth_soc.synth.generator import SyntheticGenerator

    console.print(
        f"[bold cyan]Generating synthetic logs[/bold cyan] (seed={seed}, days={days}, shift={shift})..."
    )
    generator = SyntheticGenerator(seed=seed, days=days, shift=shift)
    meta = generator.generate(out)

    table = Table(title=f"Synthetic Dataset (Output: {out})", show_header=True)
    table.add_column("File", style="cyan")
    table.add_column("Lines", justify="right")
    table.add_column("SHA-256 Digest", style="dim")

    for fname, info in meta.get("files", {}).items():
        table.add_row(fname, str(info.get("lines")), info.get("sha256")[:16] + "...")

    console.print(table)
    console.print(
        f"[green]SUCCESS:[/green] Generated {len(meta.get('files', {}))} files to [bold]{out}[/bold]\n"
    )


@app.command()
def run(
    config_path: str = typer.Option(None, "--config", "-c", help="Config file path"),
    date: str = typer.Option(None, "--date", help="Target date YYYY-MM-DD"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Use deterministic template narrator"),
    out_dir: str = typer.Option("digests", "--out", help="Output directory for digests"),
) -> None:
    """Analyze real log files and generate the morning digest."""
    from datetime import datetime
    from pathlib import Path

    from sloth_soc.config import load_config
    from sloth_soc.parsers import parse_file
    from sloth_soc.pipeline import run_pipeline_on_events, save_digest_outputs
    from sloth_soc.render.terminal import print_terminal_digest
    from sloth_soc.schema import Event

    cfg = load_config(config_path)
    target_date = date or datetime.now(UTC).strftime("%Y-%m-%d")

    console.print(
        Panel.fit(
            f"[bold green]Sloth SOC Run[/bold green] (target_date={target_date}, no_llm={no_llm})",
            border_style="cyan",
        )
    )

    events: list[Event] = []
    source_items = [
        ("sshd", cfg.sources.sshd),
        ("nginx", cfg.sources.nginx),
        ("fail2ban", cfg.sources.fail2ban),
        ("ufw", cfg.sources.ufw),
    ]

    for src_name, src_cfg in source_items:
        if src_cfg.enabled and src_cfg.path:
            p = Path(src_cfg.path)
            if p.exists():
                evs, _ = parse_file(p, source=src_name)
                events.extend(evs)

    events.sort(key=lambda e: e.ts)

    with console.status("[cyan]Analyzing events and compiling digest...[/cyan]"):
        brief, narrator_out, meta, handled = run_pipeline_on_events(
            events=events,
            target_date=target_date,
            config=cfg,
            no_llm=no_llm,
            host_label=cfg.host_label,
        )
        saved_files = save_digest_outputs(brief, narrator_out, meta, handled, out_dir=out_dir)

    print_terminal_digest(brief, narrator_out, meta, handled, console=console)

    console.print("[bold green]Digest files generated successfully:[/bold green]")
    for fmt, p in saved_files.items():
        console.print(f"  - [{fmt.upper()}] {p}")
    console.print()


@app.command()
def eval(
    all: bool = typer.Option(False, "--all", help="Run all experiments"),
    exp: str = typer.Option(
        None, "--exp", help="Comma-separated experiment list e.g. E1,E1b,E2,E3,E4,E5,E6"
    ),
) -> None:
    """Run evaluation experiments, generate figures, and output results."""
    from sloth_soc.evalkit.figures import generate_all_evaluation_figures
    from sloth_soc.evalkit.report import generate_results_markdown
    from sloth_soc.evalkit.runner import (
        run_experiment_e1,
        run_experiment_e1b,
        run_experiment_e2,
        run_experiment_e3,
        run_experiment_e5,
        run_experiment_e6,
    )
    from sloth_soc.redteam.runner import run_redteam

    targets = []
    if all:
        targets = ["E1", "E1B", "E2", "E3", "E4", "E5", "E6"]
    elif exp:
        targets = [x.strip().upper() for x in exp.split(",")]
    else:
        console.print("[yellow]Please specify --all or --exp E1,E1b,E2,E3,E4,E5,E6[/yellow]")
        return

    console.print(f"[bold cyan]Running evaluation experiments:[/bold cyan] {', '.join(targets)}")

    if "E1" in targets:
        console.print("Executing [magenta]Experiment E1[/magenta] (Detector comparison)...")
        res = run_experiment_e1()
        table = Table(title="E1: Test Split Detection Results", show_header=True)
        table.add_column("Detector", style="cyan")
        table.add_column("F1", justify="right")
        table.add_column("PR-AUC", justify="right")
        table.add_column("P@5", justify="right")
        table.add_column("R@5", justify="right")
        table.add_column("M4 Recall", justify="right")

        for det_name, det_data in res.get("detectors", {}).items():
            m = det_data["metrics"]
            m4_rec = det_data["critical_scenario_recall_m4"]
            m4_style = "[green]1.00[/green]" if m4_rec == 1.0 else f"[red]{m4_rec:.2f}[/red]"
            table.add_row(
                det_name,
                f"{m['f1']:.3f}",
                f"{m['pr_auc']:.3f}",
                f"{m['precision_at_5']:.3f}",
                f"{m['recall_at_5']:.3f}",
                m4_style,
            )
        console.print(table)
        console.print("[green]Saved results to results/E1.json[/green]\n")

    if "E1B" in targets:
        console.print(
            "Executing [magenta]Experiment E1b[/magenta] (Distribution shift generalization)..."
        )
        run_experiment_e1b()
        console.print("[green]Saved results to results/E1b.json[/green]\n")

    if "E2" in targets:
        console.print("Executing [magenta]Experiment E2[/magenta] (Label efficiency curve)...")
        run_experiment_e2()
        console.print("[green]Saved results to results/E2.json[/green]\n")

    if "E3" in targets:
        console.print("Executing [magenta]Experiment E3[/magenta] (Model sweep & faithfulness)...")
        run_experiment_e3()
        console.print("[green]Saved results to results/E3.json[/green]\n")

    if "E4" in targets:
        console.print("Executing [magenta]Experiment E4[/magenta] (Red-team injection suite)...")
        run_redteam(quick=False)
        console.print("[green]Saved results to results/E4.json[/green]\n")

    if "E5" in targets:
        console.print(
            "Executing [magenta]Experiment E5[/magenta] (No-egress offline verification)..."
        )
        run_experiment_e5()
        console.print("[green]Saved results to results/E5.json[/green]\n")

    if "E6" in targets:
        console.print("Executing [magenta]Experiment E6[/magenta] (Laziness payoff economics)...")
        run_experiment_e6()
        console.print("[green]Saved results to results/E6.json[/green]\n")

    # Generate figures and report markdown
    console.print("[cyan]Generating figures and compiling RESULTS.md...[/cyan]")
    generate_all_evaluation_figures()
    generate_results_markdown()
    console.print(
        "[green]Generated figures in results/figures/ and compiled results/RESULTS.md[/green]"
    )

    console.print("[bold green]Evaluations complete.[/bold green]")


@app.command()
def redteam(
    quick: bool = typer.Option(False, "--quick", help="Run quick CI-sized red-team suite"),
) -> None:
    """Run prompt-injection red-team suite across naive, structured, and hardened modes."""
    from sloth_soc.redteam.runner import print_redteam_table, run_redteam

    console.print(
        Panel.fit(
            f"[bold red]Sloth SOC Red-Team Suite[/bold red] (quick={quick})",
            border_style="red",
        )
    )

    with console.status(
        "[cyan]Evaluating attack success rates (ASR) against P1-P9 payloads...[/cyan]"
    ):
        report = run_redteam(quick=quick)

    print_redteam_table(report, console=console)


if __name__ == "__main__":
    app()
