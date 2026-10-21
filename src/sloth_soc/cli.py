"""Command Line Interface for Sloth SOC."""

from __future__ import annotations

import importlib.metadata
import os
import platform
import socket
import sys

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
) -> None:
    """Generate a synthetic week, run the full pipeline, and write a digest."""
    console.print(f"[yellow]Placeholder for demo (Phase 3)[/yellow]: seed={seed}, no_llm={no_llm}")


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
) -> None:
    """Analyze real log files and generate the morning digest."""
    console.print(
        f"[yellow]Placeholder for run (Phase 3)[/yellow]: config={config_path}, date={date}, no_llm={no_llm}"
    )


@app.command()
def eval(
    all: bool = typer.Option(False, "--all", help="Run all experiments E1-E6"),
    exp: str = typer.Option(None, "--exp", help="Comma-separated experiment list e.g. E1,E4"),
) -> None:
    """Run evaluation experiments and output results and figures."""
    console.print(f"[yellow]Placeholder for eval (Phase 2 & 4)[/yellow]: all={all}, exp={exp}")


@app.command()
def redteam(
    quick: bool = typer.Option(False, "--quick", help="Run quick CI-sized red-team suite"),
) -> None:
    """Run prompt-injection red-team suite across naive, structured, and hardened modes."""
    console.print(f"[yellow]Placeholder for redteam (Phase 3)[/yellow]: quick={quick}")


if __name__ == "__main__":
    app()
