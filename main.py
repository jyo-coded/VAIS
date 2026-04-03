"""
main.py
───────
VAPT Intelligence System — Professional CLI Entry Point

Usage:
    vapt scan ./project --lang auto --report html
    vapt scan main.py --lang c --report json
    vapt scan ./src --lang python --output ./results
    vapt info
"""

from __future__ import annotations
import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

console = Console()

# ── ASCII Banner ──────────────────────────────────────────────────────────────

BANNER = """
 ██╗   ██╗ █████╗ ██████╗ ████████╗
 ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝
 ██║   ██║███████║██████╔╝   ██║   
 ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   
  ╚████╔╝ ██║  ██║██║        ██║   
   ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝   
"""

VERSION  = "1.0.0"
TAGLINE  = "Agent-Orchestrated Hybrid Static Vulnerability Assessment System"
LANGS    = "C · C++ · Java · Python · Go"


def print_banner() -> None:
    text = Text(BANNER, style="bold cyan")
    panel = Panel(
        text,
        subtitle=f"[dim]{TAGLINE}[/dim]",
        subtitle_align="center",
        border_style="cyan",
        padding=(0, 2),
    )
    console.print(panel)
    console.print(f"  [dim]Version:[/dim] [white]{VERSION}[/white]   "
                  f"[dim]Languages:[/dim] [cyan]{LANGS}[/cyan]\n")


# ── Argument Parser ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vapt",
        description=TAGLINE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vapt scan ./project --lang auto --report html
  vapt scan main.c --lang c --report json --output ./results
  vapt scan ./src --lang python
  vapt info
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── scan command ──────────────────────────────────────────────────────
    scan = subparsers.add_parser(
        "scan",
        help="Analyze a file or project directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    scan.add_argument(
        "path",
        type=str,
        help="File or directory to analyze (e.g., main.c or ./project)",
    )

    scan.add_argument(
        "--lang",
        type=str,
        default="auto",
        choices=["auto", "c", "cpp", "java", "python", "go"],
        help="Language to analyze. 'auto' detects from file extensions (default: auto)",
    )

    scan.add_argument(
        "--report",
        type=str,
        default="cli",
        choices=["cli", "json", "html", "all"],
        help="Report output format (default: cli)",
    )

    scan.add_argument(
        "--output",
        type=str,
        default="./vapt_output",
        help="Directory to save output artifacts (default: ./vapt_output)",
    )

    scan.add_argument(
        "--phase",
        type=int,
        default=7,
        choices=[1, 2, 3, 4, 5, 6, 7],
        help="Run up to a specific phase only — useful for development (default: 7)",
    )

    scan.add_argument(
        "--no-patch",
        action="store_true",
        help="Skip patch generation (Phase 6) — report findings only",
    )

    scan.add_argument(
        "--benchmark",
        action="store_true",
        help="Run benchmark comparison against Cppcheck/Flawfinder (Phase 7)",
    )

    scan.add_argument(
        "--verbose",
        action="store_true",
        default=True,
        help="Show detailed progress output (default: True)",
    )

    scan.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output (overrides --verbose)",
    )

    # ── info command ──────────────────────────────────────────────────────
    subparsers.add_parser(
        "info",
        help="Show system info and verify dependencies",
    )

    return parser


# ── Command Handlers ───────────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    """Handle the 'vapt scan' command."""

    target_path = Path(args.path)
    if not target_path.exists():
        fallback_path = Path("tests/samples") / target_path.name
        if fallback_path.exists():
            args.path = str(fallback_path)
            console.print(f"[dim]Auto-resolved path to: {args.path}[/dim]")

    verbose = args.verbose and not args.quiet
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Phase 1 ───────────────────────────────────────────────────────────
    from core.phase1 import run_phase1

    phase1_result = run_phase1(
        path=args.path,
        lang_override=args.lang,
        output_dir=str(output_dir / "phase1"),
        verbose=verbose,
    )

    if not phase1_result.contexts:
        console.print("[red]✗ Phase 1 produced no output. Aborting.[/red]")
        return 1

    if args.phase == 1:
        console.print("[dim]Stopped at Phase 1 (--phase 1)[/dim]")
        return 0

    # ── Phase 2 ───────────────────────────────────────────────────────────
    from rules.engine import run_phase2

    phase2_result = run_phase2(
        phase1_result=phase1_result,
        output_dir=str(output_dir / "phase2"),
        verbose=verbose,
    )

    if args.phase == 2:
        console.print("[dim]Stopped at Phase 2 (--phase 2)[/dim]")
        return 0

    # ── Phase 3+ (coming next) ────────────────────────────────────────────
    # ── Phase 3 ───────────────────────────────────────────────────────────
    from ml.phase3 import run_phase3

    phase3_result = run_phase3(
        phase2_result=phase2_result,
        phase1_result=phase1_result,
        output_dir=str(output_dir / "phase3"),
        use_nvd_api=False,
        verbose=verbose,
    )

    if args.phase == 3:
        console.print("[dim]Stopped at Phase 3 (--phase 3)[/dim]")
        return 0

    # ── Phase 4 ───────────────────────────────────────────────────────────
    from ml.phase4 import run_phase4

    phase4_result = run_phase4(
        phase3_result=phase3_result,
        output_dir=str(output_dir / "phase4"),
        verbose=verbose,
    )

    if args.phase == 4:
        console.print("[dim]Stopped at Phase 4 (--phase 4)[/dim]")
        return 0

    # ── Phase 5 ───────────────────────────────────────────────────────────
    from agent.phase5 import run_phase5

    phase5_result = run_phase5(
        phase4_result=phase4_result,
        output_dir=str(output_dir / "phase5"),
        verbose=verbose,
    )

    if args.phase == 5:
        console.print("[dim]Stopped at Phase 5 (--phase 5)[/dim]")
        return 0

    # ── Phase 6 ───────────────────────────────────────────────────────────
    from patch.phase6 import run_phase6

    phase6_result = run_phase6(
        phase5_result=phase5_result,
        output_dir=str(output_dir / "phase6"),
        verbose=verbose,
    )

    if args.phase == 6:
        console.print("[dim]Stopped at Phase 6 (--phase 6)[/dim]")
        return 0

    # ── Phase 7 ───────────────────────────────────────────────────────────
    from report.phase7 import run_phase7

    run_phase7(
        phase1_result=phase1_result,
        phase2_result=phase2_result,
        phase3_result=phase3_result,
        phase4_result=phase4_result,
        phase5_result=phase5_result,
        phase6_result=phase6_result,
        output_dir=str(output_dir / "phase7"),
        verbose=verbose,
    )

    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Handle the 'vapt info' command — verify all dependencies."""
    console.print("\n[bold]System Dependencies Check[/bold]\n")

    checks = [
        ("tree-sitter",        "import tree_sitter"),
        ("tree-sitter-c",      "import tree_sitter_c"),
        ("tree-sitter-cpp",    "import tree_sitter_cpp"),
        ("tree-sitter-java",   "import tree_sitter_java"),
        ("tree-sitter-python", "import tree_sitter_python"),
        ("tree-sitter-go",     "import tree_sitter_go"),
        ("networkx",           "import networkx"),
        ("numpy",              "import numpy"),
        ("scikit-learn",       "import sklearn"),
        ("xgboost",            "import xgboost"),
        ("ollama",             "import ollama"),
        ("rich",               "import rich"),
        ("flask",              "import flask"),
        ("requests",           "import requests"),
    ]

    all_ok = True
    for name, import_str in checks:
        try:
            exec(import_str)
            console.print(f"  [green]✓[/green] {name}")
        except ImportError:
            console.print(
                f"  [red]✗[/red] {name} "
                f"[dim]— run: pip install -r requirements.txt[/dim]"
            )
            all_ok = False

    # Ollama server check
    try:
        import ollama
        models = ollama.list()
        
        if hasattr(models, 'models'):
            model_names = [m.model for m in models.models]
        else:
            model_names = [m.get("name", m.get("model")) for m in models.get("models", [])]
            
        if model_names:
            console.print(
                f"\n[green]✓ Ollama running[/green] "
                f"— models: {', '.join(model_names)}"
            )
        else:
            console.print(
                "\n[yellow]⚠ Ollama running but no models pulled[/yellow]"
            )
            console.print(
                "  Run: [cyan]ollama pull codellama[/cyan] "
                "or [cyan]ollama pull mistral[/cyan]"
            )
    except Exception:
        console.print(
            "\n[yellow]⚠ Ollama not running[/yellow] "
            "— start with: [cyan]ollama serve[/cyan]"
        )

    console.print()
    if all_ok:
        console.print(
            "[green]✓ All dependencies satisfied. Ready to scan.[/green]"
        )
    else:
        console.print(
            "[yellow]⚠ Some dependencies missing. "
            "Run: pip install -r requirements.txt[/yellow]"
        )

    return 0 if all_ok else 1


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    print_banner()
    
    # Auto-insert 'scan' if the first argument is likely a path or option
    if len(sys.argv) > 1 and sys.argv[1] not in ["scan", "info", "-h", "--help"]:
        sys.argv.insert(1, "scan")

    parser = build_parser()
    args = parser.parse_args()

    handlers = {
        "scan": cmd_scan,
        "info": cmd_info,
    }

    handler = handlers.get(args.command)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()