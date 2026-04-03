"""
rules/engine.py
───────────────
Phase 2 Orchestrator — the Static Rule Detection Engine.

Consumes: Phase1Result (CodeContext objects + call graphs)
Produces: VulnCollection (List[VulnObject]) → vuln_raw.json

The engine:
  1. Selects rules for each language
  2. Walks the AST from CodeContext.ast_json
  3. Dispatches each node to relevant rules
  4. Collects and deduplicates findings
  5. Enriches with reachability data from call graph
"""

from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

from core.code_context import Language, CodeContext
from rules.vuln_object import VulnCollection, Severity
from rules.base_rule import BaseRule
from rules.c_rules import C_RULES
from rules.python_rules import PYTHON_RULES
from rules.go_rules import GO_RULES
from rules.java_rules import JAVA_RULES
from rules.cpp_rules import CPP_RULES
from core.standards_engine import StandardsEngine
from core.taint_analyzer import TaintAnalyzer

console = Console()

# ─── Language → Rule registry ────────────────────────────────────────────────

RULES_BY_LANGUAGE: dict[Language, list[BaseRule]] = {
    Language.C:      C_RULES,
    Language.CPP:    CPP_RULES,
    Language.JAVA:   JAVA_RULES,
    Language.PYTHON: PYTHON_RULES,
    Language.GO:     GO_RULES,
}


# ─── Phase 2 Result ──────────────────────────────────────────────────────────

class Phase2Result:
    """
    Output contract of Phase 2.
    Phase 3 (feature extraction) receives exactly this object.
    """

    def __init__(self):
        self.collection:  VulnCollection = VulnCollection()
        self.errors:      list[str]      = []
        self.duration_s:  float          = 0.0
        self.files_scanned: int          = 0
        self.rules_fired:   int          = 0

    def save(self, output_dir: str | Path) -> None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        self.collection.save(str(out / "vuln_raw.json"))
        console.print(f"[dim]  Phase 2 artifacts saved → {out}/[/dim]")

    def summary(self) -> dict:
        s = self.collection.summary()
        s.update({
            "files_scanned": self.files_scanned,
            "rules_fired":   self.rules_fired,
            "duration_s":    round(self.duration_s, 3),
            "errors":        self.errors,
        })
        return s

    def __repr__(self) -> str:
        s = self.collection.summary()
        return (f"Phase2Result(total={s['total']}, critical={s['critical']}, "
                f"high={s['high']}, medium={s['medium']}, low={s['low']})")


# ─── Engine ───────────────────────────────────────────────────────────────────

class RuleEngine:
    """
    Walks CodeContext AST nodes and dispatches rules.
    One engine instance per scan session.
    """

    def __init__(self):
        self._rules = RULES_BY_LANGUAGE

    def scan_context(
        self,
        context: CodeContext,
        collection: VulnCollection,
    ) -> int:
        """
        Scan a single CodeContext.
        Returns the number of new findings added.
        """
        rules = self._rules.get(context.language, [])
        if not rules:
            return 0

        source_lines = self._load_source_lines(context.source_file)
        before = len(collection)

        if context.ast_json:
            # AST-based rules: walk nodes and dispatch
            self._walk_ast(
                node=context.ast_json,
                context=context,
                collection=collection,
                source_lines=source_lines,
                rules=rules,
            )
        else:
            # Fallback: line-based rules only (for files that parsed with errors)
            self._run_line_rules(
                context=context,
                collection=collection,
                source_lines=source_lines,
                rules=rules,
            )

        return len(collection) - before

    def _walk_ast(
        self,
        node: dict,
        context: CodeContext,
        collection: VulnCollection,
        source_lines: list[str],
        rules: list[BaseRule],
    ) -> None:
        """
        Recursive AST walk.
        For each node, dispatch all rules whose node_types match.
        Also runs rules that match empty node_types (line-based scanners).
        """
        node_type = node.get("type", "")

        for rule in rules:
            try:
                # Dispatch if: rule targets this node type OR rule has no node type filter
                if not rule.node_types or node_type in rule.node_types:
                    rule.check(node, context, collection, source_lines)
            except Exception as e:
                pass  # Never let a rule crash the engine

        for child in node.get("children", []):
            self._walk_ast(child, context, collection, source_lines, rules)

    def _run_line_rules(
        self,
        context: CodeContext,
        collection: VulnCollection,
        source_lines: list[str],
        rules: list[BaseRule],
    ) -> None:
        """
        Fallback for files without a valid AST.
        Passes an empty dict node — rules that do line-scanning still work.
        """
        for rule in rules:
            try:
                rule.check({}, context, collection, source_lines)
            except Exception:
                pass

    def _load_source_lines(self, file_path: str) -> list[str]:
        try:
            return Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []


# ─── Phase 2 entry point ─────────────────────────────────────────────────────

def run_phase2(
    phase1_result,
    output_dir: Optional[str] = None,
    verbose: bool = True,
) -> Phase2Result:
    """
    Run Phase 2 end-to-end.

    Args:
        phase1_result:  Phase1Result from Phase 1
        output_dir:     If set, saves vuln_raw.json here
        verbose:        Print progress to console

    Returns:
        Phase2Result — typed output contract consumed by Phase 3
    """
    start = time.time()
    result = Phase2Result()
    engine = RuleEngine()

    if verbose:
        console.print()
        console.rule("[bold red]PHASE 2 — Static Rule Detection[/bold red]", style="red")

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
        task = progress.add_task(
            "  Running rules...", total=len(phase1_result.contexts)
        )

        for ctx in phase1_result.contexts:
            progress.update(
                task,
                description=f"  Scanning [cyan]{Path(ctx.source_file).name}[/cyan]"
            )
            try:
                found = engine.scan_context(ctx, result.collection)
                result.files_scanned += 1
                result.rules_fired += found
            except Exception as e:
                result.errors.append(f"{ctx.source_file}: {e}")

            progress.advance(task)

    result.duration_s = time.time() - start

    # ── Taint & Standards Enhancement ──
    if verbose:
        console.print("  [dim]Attaching Standards citations and Taint Analysis...[/dim]")
    
    standards = StandardsEngine()
    taint_analyzer = TaintAnalyzer()

    for vuln in result.collection._vulns:
        vuln.standards_citation = standards.format_citation(vuln.cwe.value)

    if phase1_result.merged_call_graph:
        taint_analyzer.analyze(phase1_result.merged_call_graph.graph, result.collection._vulns)

    if output_dir:
        result.save(output_dir)

    if verbose:
        _print_phase2_summary(result)

    return result


def _print_phase2_summary(result: Phase2Result) -> None:
    """Print a rich-formatted Phase 2 summary."""
    s = result.summary()
    coll = result.collection

    # Summary stats table
    table = Table(show_header=False, border_style="dim", padding=(0, 2))
    table.add_column("Key", style="dim")
    table.add_column("Value", style="white")

    table.add_row("Files scanned",   str(s["files_scanned"]))
    table.add_row("Total findings",  str(s["total"]))
    table.add_row("Duration",        f"{s['duration_s']}s")
    console.print(table)

    if s["total"] == 0:
        console.print("[green]  No vulnerabilities detected.[/green]")
        return

    # Findings breakdown table
    findings_table = Table(
        title="Findings by Severity",
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        padding=(0, 2),
    )
    findings_table.add_column("Severity",  style="bold")
    findings_table.add_column("Count",     justify="right")
    findings_table.add_column("Top Finding")

    severity_colors = {
        "CRITICAL": "red",
        "HIGH":     "orange3",
        "MEDIUM":   "yellow",
        "LOW":      "blue",
        "INFO":     "dim",
    }

    for sev_name, color in severity_colors.items():
        sev = Severity(sev_name)
        vulns = coll.by_severity(sev)
        if vulns:
            top = vulns[0].title
            findings_table.add_row(
                f"[{color}]{sev_name}[/{color}]",
                f"[{color}]{len(vulns)}[/{color}]",
                f"[dim]{top}[/dim]",
            )

    console.print(findings_table)

    # Per-language breakdown
    if s.get("by_lang"):
        lang_parts = " · ".join(
            f"[cyan]{lang}[/cyan]: {count}"
            for lang, count in s["by_lang"].items()
        )
        console.print(f"  [dim]By language:[/dim] {lang_parts}")

    console.print(f"\n[green]✓ Phase 2 complete[/green] [dim]→ VulnCollection ready for Phase 3[/dim]\n")