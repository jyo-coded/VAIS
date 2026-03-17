"""
report/cli_report.py
────────────────────
Phase 7: CLI Report Generator.

Produces a Rich terminal report with:
  - Executive summary
  - Severity breakdown
  - Top findings table
  - Per-language breakdown
  - ML risk scores
  - Patch summary
  - Fix rate
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box

from rules.vuln_object import VulnObject, Severity

console = Console()

SEV_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}


def generate_cli_report(
    all_results: dict,
    output_path: Optional[str] = None,
) -> str:
    """
    Generate a full CLI report from aggregated phase results.

    Args:
        all_results:  dict with keys: phase1, phase2, phase3, phase4, phase5, phase6
        output_path:  if set, write report to this .txt file

    Returns:
        Plain-text version of the report
    """
    from io import StringIO
    buf = StringIO()
    file_console = Console(file=buf, width=100, highlight=False)

    _render_report(file_console, all_results)

    # Also print to terminal
    _render_report(console, all_results)

    report_text = buf.getvalue()

    if output_path:
        Path(output_path).write_text(report_text, encoding="utf-8")

    return report_text


def _render_report(con: Console, r: dict) -> None:
    p2 = r.get("phase2")
    p4 = r.get("phase4")
    p5 = r.get("phase5")
    p6 = r.get("phase6")

    vulns        = p4.sorted_by_risk() if p4 else []
    n_total      = len(vulns)
    n_critical   = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
    n_high       = sum(1 for v in vulns if v.severity == Severity.HIGH)
    n_medium     = sum(1 for v in vulns if v.severity == Severity.MEDIUM)
    n_low        = sum(1 for v in vulns if v.severity == Severity.LOW)
    n_patched    = p6.n_patched    if p6 else 0
    fix_rate     = p6.total_fix_rate if p6 else 0.0
    n_decisions  = p5.n_decisions  if p5 else 0

    # ── Header ────────────────────────────────────────────────────────────
    con.print()
    con.print(Panel(
        Text.assemble(
            ("VAPT INTELLIGENCE SYSTEM\n", "bold cyan"),
            ("Agent-Orchestrated Hybrid Static Vulnerability Assessment\n", "dim"),
            (f"Findings: {n_total}  |  ", "white"),
            (f"Critical: {n_critical}  ", "bold red"),
            (f"High: {n_high}  ", "red"),
            (f"Medium: {n_medium}  ", "yellow"),
            (f"Low: {n_low}", "cyan"),
        ),
        title="[bold]Security Assessment Report[/bold]",
        border_style="cyan",
    ))

    # ── Executive Summary ────────────────────────────────────────────────
    con.print("\n[bold cyan]EXECUTIVE SUMMARY[/bold cyan]")

    summary_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    summary_table.add_column("Metric", style="dim", width=28)
    summary_table.add_column("Value",  style="white")

    summary_table.add_row("Total vulnerabilities",  str(n_total))
    summary_table.add_row("Critical / High",         f"[bold red]{n_critical}[/] / [red]{n_high}[/]")
    summary_table.add_row("Medium / Low",            f"[yellow]{n_medium}[/] / [cyan]{n_low}[/]")
    summary_table.add_row("Patch decisions made",   str(n_decisions))
    summary_table.add_row("Patches applied",         str(n_patched))
    summary_table.add_row("Automated fix rate",
        f"[green]{fix_rate:.1%}[/]" if fix_rate >= 0.5 else f"[yellow]{fix_rate:.1%}[/]"
    )

    if vulns:
        avg_risk = sum(v.risk_score or 0 for v in vulns) / len(vulns)
        avg_exp  = sum(v.exploit_prob or 0 for v in vulns) / len(vulns)
        summary_table.add_row("Avg risk score",      f"{avg_risk:.3f}")
        summary_table.add_row("Avg exploit prob",    f"{avg_exp:.1%}")

    con.print(summary_table)

    # ── Top Findings ──────────────────────────────────────────────────────
    con.print("\n[bold cyan]TOP FINDINGS (by risk)[/bold cyan]")
    findings_table = Table(
        show_header=True,
        header_style="bold dim",
        box=box.SIMPLE_HEAVY,
        padding=(0, 1),
    )
    findings_table.add_column("ID",         style="cyan",  width=14)
    findings_table.add_column("Severity",   width=10)
    findings_table.add_column("CWE",        style="dim",   width=10)
    findings_table.add_column("Function",   width=20)
    findings_table.add_column("Line",       justify="right", width=6)
    findings_table.add_column("Risk",       justify="right", width=6)
    findings_table.add_column("Exploit%",   justify="right", width=9)
    findings_table.add_column("Strategy",   style="dim")

    for v in vulns[:20]:
        sev_color = SEV_COLORS.get(v.severity.value, "white")
        risk_color = "red" if (v.risk_score or 0) >= 0.7 else "yellow" if (v.risk_score or 0) >= 0.4 else "green"
        strategy = (v.patch_strategy or "—")[:30]

        findings_table.add_row(
            v.vuln_id,
            f"[{sev_color}]{v.severity.value}[/]",
            v.cwe.value,
            (v.function_name or "—")[:18],
            str(v.line_start),
            f"[{risk_color}]{v.risk_score:.3f}[/]" if v.risk_score is not None else "—",
            f"{v.exploit_prob:.0%}" if v.exploit_prob is not None else "—",
            strategy,
        )

    if len(vulns) > 20:
        findings_table.add_row(
            f"... +{len(vulns)-20} more", "", "", "", "", "", "", ""
        )
    con.print(findings_table)

    # ── Patch Results ─────────────────────────────────────────────────────
    if p6 and p6.patch_results:
        con.print("\n[bold cyan]PATCH RESULTS[/bold cyan]")
        patch_table = Table(
            show_header=True,
            header_style="bold dim",
            box=box.SIMPLE,
            padding=(0, 1),
        )
        patch_table.add_column("Vuln ID",  style="cyan", width=14)
        patch_table.add_column("Strategy", width=34)
        patch_table.add_column("Status",   width=12)

        for pr in p6.patch_results:
            status = "[green]✓ patched[/]" if pr.success else "[red]✗ failed[/]"
            patch_table.add_row(pr.vuln_id, pr.strategy, status)

        con.print(patch_table)

        # Verification
        for vr in p6.verification:
            con.print(
                f"  [dim]Re-analysis:[/dim] "
                f"[cyan]{Path(vr.patched_file).name}[/cyan]  "
                f"Before=[red]{vr.vulns_before}[/red]  "
                f"After=[green]{vr.vulns_after}[/green]  "
                f"Fixed=[green]{vr.vulns_fixed}[/green]  "
                f"Rate=[bold]{vr.fix_rate:.1%}[/bold]"
            )

    # ── Footer ────────────────────────────────────────────────────────────
    con.print()
    con.print(Panel(
        Text.assemble(
            ("Assessment complete. ", "bold green"),
            (f"{n_total} vulnerabilities found across C / Python / Go. ", "white"),
            (f"{n_patched} patches applied. ", "white"),
            (f"Fix rate: {fix_rate:.1%}.", "bold"),
        ),
        border_style="green",
    ))
    con.print()