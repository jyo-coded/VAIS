"""
core/phase1.py
──────────────
Phase 1 Orchestrator.
This is the single function downstream code calls to run Phase 1 end-to-end.

Input:  raw path(s) + CLI flags
Output: list of (CodeContext, CallGraph) pairs — one per parsed file

Usage:
    from core.phase1 import run_phase1
    results = run_phase1(path="./project", lang_override="auto")
    for ctx, cg in results:
        print(ctx)
        print(cg)
"""

from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from core.language_router import LanguageRouter
from core.parser import ASTParser
from core.call_graph import CallGraph
from core.code_context import CodeContext, Language

console = Console()


# ─── Result container ────────────────────────────────────────────────────────

class Phase1Result:
    """
    Output contract of Phase 1.
    Phase 2 receives exactly this object — nothing else.
    """

    def __init__(self):
        self.contexts:    list[CodeContext] = []
        self.call_graphs: dict[str, CallGraph] = {}   # keyed by source_file
        self.merged_call_graph: Optional[CallGraph] = None
        self.errors:      list[str] = []
        self.duration_s:  float = 0.0

    def add(self, ctx: CodeContext, cg: CallGraph) -> None:
        self.contexts.append(ctx)
        self.call_graphs[ctx.source_file] = cg

    def get_context(self, file: str) -> Optional[CodeContext]:
        return next((c for c in self.contexts if c.source_file == file), None)

    def get_call_graph(self, file: str) -> Optional[CallGraph]:
        return self.call_graphs.get(file)

    def save_all(self, output_dir: str | Path) -> None:
        """Save all CodeContexts and call graphs to disk."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        for ctx in self.contexts:
            stem = Path(ctx.source_file).stem
            ctx.save(str(out / f"{stem}_context.json"))

        if self.merged_call_graph:
            self.merged_call_graph.save(str(out / "call_graph.gml"))
            with open(out / "call_graph.json", "w") as f:
                json.dump(self.merged_call_graph.to_dict(), f, indent=2)

        console.print(f"[dim]  Phase 1 artifacts saved → {out}/[/dim]")

    @property
    def success_count(self) -> int:
        return sum(1 for c in self.contexts if c.parse_success)

    @property
    def total_functions(self) -> int:
        return sum(len(c.functions) for c in self.contexts)

    @property
    def total_call_sites(self) -> int:
        return sum(len(c.call_sites) for c in self.contexts)

    def summary(self) -> dict:
        return {
            "files_parsed":    len(self.contexts),
            "files_succeeded": self.success_count,
            "total_functions": self.total_functions,
            "total_call_sites": self.total_call_sites,
            "errors":          self.errors,
            "duration_s":      round(self.duration_s, 3),
            "languages":       list({c.language.value for c in self.contexts}),
        }

    def __repr__(self) -> str:
        return (
            f"Phase1Result(files={len(self.contexts)}, "
            f"ok={self.success_count}, "
            f"functions={self.total_functions})"
        )


# ─── Main entry point ─────────────────────────────────────────────────────────

def run_phase1(
    path: str,
    lang_override: Optional[str] = "auto",
    output_dir: Optional[str]   = None,
    verbose: bool               = True,
) -> Phase1Result:
    """
    Run Phase 1 end-to-end.

    Args:
        path:           File or directory to analyze
        lang_override:  'auto', 'c', 'python', 'go', or None
        output_dir:     If set, saves JSON artifacts here
        verbose:        Print progress to console

    Returns:
        Phase1Result — the typed output contract consumed by Phase 2
    """

    start = time.time()
    result = Phase1Result()

    if verbose:
        console.print()
        console.rule("[bold cyan]PHASE 1 — Structural Parsing[/bold cyan]", style="cyan")

    # ── Step 1: Resolve files ─────────────────────────────────────────────
    try:
        router = LanguageRouter(path=path, lang_override=lang_override, verbose=verbose)
        targets = router.resolve()
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]✗ Language Router Error:[/red] {e}")
        result.errors.append(str(e))
        return result

    # ── Step 2: Parse each file ───────────────────────────────────────────
    try:
        parser = ASTParser()
    except RuntimeError as e:
        console.print(f"[red]✗ Parser Init Error:[/red] {e}")
        result.errors.append(str(e))
        return result

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        disable=not verbose,
    ) as progress:
        task = progress.add_task("  Parsing files...", total=len(targets))

        for file_path, language in targets:
            progress.update(task, description=f"  Parsing [cyan]{file_path.name}[/cyan]")

            try:
                ctx = parser.parse(file_path, language)
                cg  = CallGraph.from_context(ctx)
                result.add(ctx, cg)

                if not ctx.parse_success:
                    for err in ctx.parse_errors:
                        result.errors.append(f"{file_path.name}: {err}")

            except Exception as e:
                err_msg = f"Failed to parse {file_path}: {e}"
                result.errors.append(err_msg)
                if verbose:
                    console.print(f"[red]  ✗ {err_msg}[/red]")

            progress.advance(task)

    # ── Step 3: Merge call graphs ─────────────────────────────────────────
    if result.contexts:
        result.merged_call_graph = CallGraph.from_contexts(result.contexts)

    # ── Step 4: Save artifacts ────────────────────────────────────────────
    if output_dir and result.contexts:
        result.save_all(output_dir)

    result.duration_s = time.time() - start

    # ── Step 5: Print summary ─────────────────────────────────────────────
    if verbose:
        _print_phase1_summary(result)

    return result


def _print_phase1_summary(result: Phase1Result) -> None:
    """Print a clean summary of Phase 1 results."""
    from rich.table import Table

    s = result.summary()

    table = Table(
        show_header=False,
        border_style="dim",
        padding=(0, 2),
    )
    table.add_column("Key", style="dim")
    table.add_column("Value", style="white")

    status = "[green]✓ All succeeded[/green]" if not result.errors else f"[yellow]⚠ {len(result.errors)} error(s)[/yellow]"

    table.add_row("Files parsed",    str(s["files_parsed"]))
    table.add_row("Status",          status)
    table.add_row("Languages",       " · ".join(s["languages"]))
    table.add_row("Functions found", str(s["total_functions"]))
    table.add_row("Call sites",      str(s["total_call_sites"]))
    table.add_row("Duration",        f"{s['duration_s']}s")

    if result.merged_call_graph:
        cg_stats = result.merged_call_graph.stats
        table.add_row("Call graph nodes", str(cg_stats["functions"]))
        table.add_row("Call graph edges", str(cg_stats["call_edges"]))
        table.add_row("Entry points",     ", ".join(cg_stats["entry_points"]) or "none")

    console.print(table)

    if result.errors:
        console.print("\n[yellow]Parse warnings:[/yellow]")
        for err in result.errors:
            console.print(f"  [dim]• {err}[/dim]")

    console.print(f"\n[green]✓ Phase 1 complete[/green] [dim]→ CodeContext ready for Phase 2[/dim]\n")