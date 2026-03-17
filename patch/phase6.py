"""
patch/phase6.py
───────────────
Phase 6 Orchestrator — Patch Engine + Re-Verification.

Consumes: Phase5Result (decisions: List[(vuln_id, strategy)] + scored_vulns)
Produces: Phase6Result containing:
          - patch_results:       List[PatchResult] per decision
          - verification:        List[VerificationResult] per file
          - patched_files:       {original: patched} paths
          - patch.diff artifact
          - verification.json artifact
"""

from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from patch.patch_engine import PatchEngine, PatchResult
from patch.verifier import PatchVerifier, VerificationResult

console = Console()


# ─── Phase 6 Result ──────────────────────────────────────────────────────────

class Phase6Result:
    """
    Output contract of Phase 6.
    Phase 7 (Report Generator) receives exactly this object.
    """

    def __init__(self):
        self.patch_results:   list[PatchResult]        = []
        self.verification:    list[VerificationResult] = []
        self.patched_files:   dict[str, str]           = {}
        self.errors:          list[str]                = []
        self.duration_s:      float                    = 0.0

    @property
    def n_patched(self) -> int:
        return sum(1 for r in self.patch_results if r.success)

    @property
    def n_failed(self) -> int:
        return sum(1 for r in self.patch_results if not r.success)

    @property
    def total_fix_rate(self) -> float:
        if not self.verification:
            return 0.0
        total_before = sum(v.vulns_before for v in self.verification)
        total_after  = sum(v.vulns_after  for v in self.verification)
        if total_before == 0:
            return 1.0
        return round((total_before - total_after) / total_before, 4)

    def save(self, output_dir: str | Path) -> None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # verification.json
        with open(out / "verification.json", "w") as f:
            json.dump({
                "total_patched":    self.n_patched,
                "total_failed":     self.n_failed,
                "total_fix_rate":   self.total_fix_rate,
                "patch_results":    [r.to_dict() for r in self.patch_results],
                "verification":     [v.to_dict() for v in self.verification],
                "patched_files":    self.patched_files,
            }, f, indent=2)

        console.print(f"[dim]  Phase 6 artifacts saved → {out}/[/dim]")

    def summary(self) -> dict:
        return {
            "total_decisions": len(self.patch_results),
            "n_patched":       self.n_patched,
            "n_failed":        self.n_failed,
            "fix_rate":        self.total_fix_rate,
            "patched_files":   list(self.patched_files.values()),
            "duration_s":      round(self.duration_s, 3),
            "errors":          self.errors,
        }

    def __repr__(self) -> str:
        s = self.summary()
        return (f"Phase6Result(patched={s['n_patched']}, "
                f"failed={s['n_failed']}, fix_rate={s['fix_rate']:.1%})")


# ─── Phase 6 Entry Point ─────────────────────────────────────────────────────

def run_phase6(
    phase5_result,
    output_dir:  Optional[str] = None,
    verbose:     bool          = True,
) -> Phase6Result:
    """
    Run Phase 6 end-to-end.

    Args:
        phase5_result:  Phase5Result from Phase 5
        output_dir:     If set, saves patched files + artifacts here
        verbose:        Print progress to console

    Returns:
        Phase6Result — typed output contract consumed by Phase 7
    """
    start  = time.time()
    result = Phase6Result()

    if verbose:
        console.print()
        console.rule(
            "[bold green]PHASE 6 — Patch Engine[/bold green]",
            style="green"
        )

    # ── Validate input ────────────────────────────────────────────────────
    if not phase5_result.decisions:
        console.print("[yellow]  No patch decisions to apply.[/yellow]")
        result.duration_s = time.time() - start
        return result

    decisions    = phase5_result.decisions
    scored_vulns = phase5_result.scored_vulns

    if verbose:
        console.print(
            f"  Applying [cyan]{len(decisions)}[/cyan] patch decisions..."
        )

    # ── Step 1: Apply patches ─────────────────────────────────────────────
    patch_dir = Path(output_dir or "./vapt_output/phase6")
    engine    = PatchEngine()

    try:
        patch_results, patched_files = engine.apply_all(
            decisions, scored_vulns, patch_dir
        )
        result.patch_results = patch_results
        result.patched_files = patched_files
    except Exception as e:
        result.errors.append(f"Patch engine failed: {e}")
        if verbose:
            console.print(f"[red]✗ Patch error: {e}[/red]")
        result.duration_s = time.time() - start
        return result

    # ── Step 2: Verify patches ────────────────────────────────────────────
    if verbose:
        console.print("  [dim]Re-running Phase 1+2 on patched files...[/dim]")

    verifier = PatchVerifier()
    try:
        verification = verifier.verify(scored_vulns, patched_files)
        result.verification = verification
    except Exception as e:
        result.errors.append(f"Verification failed: {e}")

    # ── Step 3: Save artifacts ────────────────────────────────────────────
    if output_dir:
        result.save(output_dir)

    result.duration_s = time.time() - start

    if verbose:
        _print_phase6_summary(result)

    return result


def _print_phase6_summary(result: Phase6Result) -> None:
    """Print rich Phase 6 summary."""

    # Patch results table
    patch_table = Table(
        title="Patch Results",
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        padding=(0, 2),
    )
    patch_table.add_column("Vuln ID",    style="cyan")
    patch_table.add_column("Strategy",  style="white")
    patch_table.add_column("Status",    justify="center")
    patch_table.add_column("Detail",    style="dim")

    for r in result.patch_results:
        status = "[green]✓ patched[/green]" if r.success else "[red]✗ failed[/red]"
        detail = r.description if r.success else r.error[:60]
        patch_table.add_row(r.vuln_id, r.strategy, status, detail)

    console.print(patch_table)

    # Verification summary
    if result.verification:
        for v in result.verification:
            ver_table = Table(
                title=f"Verification: {Path(v.patched_file).name}",
                show_header=False,
                border_style="dim",
                padding=(0, 2),
            )
            ver_table.add_column("Key",   style="dim")
            ver_table.add_column("Value", style="white")
            ver_table.add_row("Vulns before", str(v.vulns_before))
            ver_table.add_row("Vulns after",  str(v.vulns_after))
            ver_table.add_row(
                "Vulns fixed",
                f"[green]{v.vulns_fixed}[/green]"
            )
            ver_table.add_row(
                "Fix rate",
                f"[{'green' if v.fix_rate >= 0.5 else 'yellow'}]{v.fix_rate:.1%}[/]"
            )
            if v.error:
                ver_table.add_row("Error", f"[red]{v.error}[/red]")
            console.print(ver_table)

    # Summary stats
    stats = Table(show_header=False, border_style="dim", padding=(0, 2))
    stats.add_column("Key",   style="dim")
    stats.add_column("Value", style="white")
    stats.add_row("Patches applied", f"[green]{result.n_patched}[/green]")
    stats.add_row("Patches failed",  f"[red]{result.n_failed}[/red]" if result.n_failed else "0")
    stats.add_row("Overall fix rate", f"{result.total_fix_rate:.1%}")
    stats.add_row("Duration",         f"{result.duration_s:.2f}s")
    for pf in result.patched_files.values():
        stats.add_row("Patched file", Path(pf).name)
    console.print(stats)

    console.print(
        f"\n[green]✓ Phase 6 complete[/green] "
        f"[dim]→ Patch results ready for Phase 7 (Report)[/dim]\n"
    )