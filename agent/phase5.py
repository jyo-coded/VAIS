"""
agent/phase5.py
───────────────
Phase 5 Orchestrator — Agentic Orchestration Layer.

Consumes: Phase4Result (scored_vulns: List[VulnObject] with ML scores)
Produces: Phase5Result containing:
          - decisions: List[(vuln_id, strategy)] for Phase 6
          - agent_trace.json artifact
          - VulnObjects with patch_strategy attached
"""

from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from agent.ollama_agent import OllamaAgent, AgentTrace
from rules.vuln_object import VulnObject

console = Console()


# ─── Phase 5 Result ──────────────────────────────────────────────────────────

class Phase5Result:
    """
    Output contract of Phase 5.
    Phase 6 (Patch Engine) receives exactly this object.
    """

    def __init__(self):
        self.decisions:      list[tuple[str, str]] = []  # (vuln_id, strategy)
        self.scored_vulns:   list[VulnObject]      = []  # enriched with patch_strategy
        self.trace:          AgentTrace | None     = None
        self.agent_mode:     str                   = ""
        self.errors:         list[str]             = []
        self.duration_s:     float                 = 0.0

    @property
    def n_decisions(self) -> int:
        return len(self.decisions)

    def save(self, output_dir: str | Path) -> None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # agent_trace.json
        if self.trace:
            with open(out / "agent_trace.json", "w") as f:
                json.dump(self.trace.to_dict(), f, indent=2)

        # decisions.json
        with open(out / "decisions.json", "w") as f:
            json.dump({
                "total":      self.n_decisions,
                "agent_mode": self.agent_mode,
                "decisions": [
                    {"vuln_id": vid, "strategy": strat}
                    for vid, strat in self.decisions
                ],
            }, f, indent=2)

        console.print(f"[dim]  Phase 5 artifacts saved → {out}/[/dim]")

    def summary(self) -> dict:
        return {
            "n_decisions":  self.n_decisions,
            "agent_mode":   self.agent_mode,
            "duration_s":   round(self.duration_s, 3),
            "errors":       self.errors,
            "decisions":    [
                {"vuln_id": vid, "strategy": strat}
                for vid, strat in self.decisions
            ],
        }

    def __repr__(self) -> str:
        return (f"Phase5Result(decisions={self.n_decisions}, "
                f"mode={self.agent_mode})")


# ─── Phase 5 Entry Point ─────────────────────────────────────────────────────

def run_phase5(
    phase4_result,
    output_dir:  Optional[str] = None,
    model:       str           = "codellama",
    verbose:     bool          = True,
) -> Phase5Result:
    """
    Run Phase 5 end-to-end.

    Args:
        phase4_result:  Phase4Result from Phase 4
        output_dir:     If set, saves agent_trace.json + decisions.json here
        model:          Ollama model to use (codellama or mistral)
        verbose:        Print progress to console

    Returns:
        Phase5Result — typed output contract consumed by Phase 6
    """
    start  = time.time()
    result = Phase5Result()

    if verbose:
        console.print()
        console.rule(
            "[bold blue]PHASE 5 — Agentic Orchestration[/bold blue]",
            style="blue"
        )

    # ── Validate input ────────────────────────────────────────────────────
    if phase4_result.n_vulns == 0:
        console.print("[yellow]  No vulnerabilities to process.[/yellow]")
        result.duration_s = time.time() - start
        return result

    scored_vulns = phase4_result.sorted_by_risk()
    result.scored_vulns = scored_vulns

    # ── Initialize agent ──────────────────────────────────────────────────
    agent = OllamaAgent(model=model)
    ollama_available = agent.initialize()

    if verbose:
        if ollama_available:
            console.print(
                f"  [green]✓ Ollama connected[/green] — "
                f"model: [cyan]{agent._active_model}[/cyan]"
            )
        else:
            console.print(
                "  [yellow]⚠ Ollama not available[/yellow] — "
                "using rule-based fallback"
            )
        console.print(
            f"  Processing [cyan]{len(scored_vulns)}[/cyan] vulnerabilities "
            f"in priority order..."
        )

    result.agent_mode = agent.mode

    # ── Run agent loop ────────────────────────────────────────────────────
    try:
        trace = agent.run(scored_vulns)
        result.trace = trace

        # Extract decisions from trace
        result.decisions = [
            (d["vuln_id"], d["strategy"])
            for d in trace.decisions
        ]

        if trace.errors:
            result.errors.extend(trace.errors)

    except Exception as e:
        result.errors.append(f"Agent loop failed: {e}")
        if verbose:
            console.print(f"[red]✗ Agent error: {e}[/red]")

    # ── Save artifacts ────────────────────────────────────────────────────
    if output_dir:
        result.save(output_dir)

    result.duration_s = time.time() - start

    if verbose:
        _print_phase5_summary(result)

    return result


def _print_phase5_summary(result: Phase5Result) -> None:
    """Print rich Phase 5 summary."""

    mode_str = (
        f"[green]LLM ({result.agent_mode})[/green]"
        if result.agent_mode.startswith("llm")
        else "[yellow]Rule-based fallback[/yellow]"
    )

    # Stats table
    stats = Table(show_header=False, border_style="dim", padding=(0, 2))
    stats.add_column("Key",   style="dim")
    stats.add_column("Value", style="white")
    stats.add_row("Agent mode",    mode_str)
    stats.add_row("Decisions made", str(result.n_decisions))
    stats.add_row("Errors",        str(len(result.errors)))
    stats.add_row("Duration",      f"{result.duration_s:.2f}s")
    console.print(stats)

    # Decisions table
    if result.decisions:
        dec_table = Table(
            title="Patch Strategy Decisions",
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            padding=(0, 2),
        )
        dec_table.add_column("Vuln ID",  style="cyan")
        dec_table.add_column("Strategy", style="white")

        for vuln_id, strategy in result.decisions[:15]:
            dec_table.add_row(vuln_id, strategy)

        if len(result.decisions) > 15:
            dec_table.add_row("...", f"({len(result.decisions) - 15} more)")

        console.print(dec_table)

    console.print(
        f"\n[green]✓ Phase 5 complete[/green] "
        f"[dim]→ {result.n_decisions} decisions ready for Phase 6 (Patch Engine)[/dim]\n"
    )