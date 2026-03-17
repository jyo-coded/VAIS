"""
ml/phase4.py
────────────
Phase 4 Orchestrator — ML Risk & Exploitability Scoring.

Consumes: Phase3Result (X: ndarray + vulns: List[VulnObject])
Produces: Phase4Result containing:
          - scored_vulns: List[VulnObject] with exploit_prob + risk_score + ml_severity
          - model metrics (accuracy, F1, AUC-ROC, MAE, R2)
          - saved models: model_clf.pkl, model_reg.pkl, scaler.pkl
          - scored_vulns.json artifact
"""

from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Optional

import numpy as np
from rich.console import Console
from rich.table import Table

from ml.dataset import DatasetBuilder
from ml.trainer import ModelTrainer
from ml.predictor import MLPredictor
from rules.vuln_object import VulnObject, Severity

console = Console()


# ─── Phase 4 Result ──────────────────────────────────────────────────────────

class Phase4Result:
    """
    Output contract of Phase 4.
    Phase 5 (agent) receives exactly this object.
    """

    def __init__(self):
        self.scored_vulns: list[VulnObject] = []
        self.model_dir:    str              = ""
        self.metrics:      dict             = {}
        self.errors:       list[str]        = []
        self.duration_s:   float            = 0.0

    @property
    def n_vulns(self) -> int:
        return len(self.scored_vulns)

    def sorted_by_risk(self) -> list[VulnObject]:
        """Return vulns sorted by composite_risk descending — agent priority order."""
        return sorted(
            self.scored_vulns,
            key=lambda v: v.composite_risk,
            reverse=True
        )

    def save(self, output_dir: str | Path) -> None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # scored_vulns.json
        with open(out / "scored_vulns.json", "w") as f:
            json.dump({
                "total":  self.n_vulns,
                "metrics": self.metrics,
                "vulnerabilities": [v.to_dict() for v in self.sorted_by_risk()],
            }, f, indent=2)

        # metrics.json
        with open(out / "metrics.json", "w") as f:
            json.dump(self.metrics, f, indent=2)

        console.print(f"[dim]  Phase 4 artifacts saved → {out}/[/dim]")

    def summary(self) -> dict:
        scored = [v for v in self.scored_vulns if v.exploit_prob is not None]
        high_risk = [v for v in scored if v.composite_risk >= 0.7]
        return {
            "total":       self.n_vulns,
            "scored":      len(scored),
            "high_risk":   len(high_risk),
            "avg_exploit_prob": round(
                float(np.mean([v.exploit_prob for v in scored])) if scored else 0.0, 4
            ),
            "avg_risk_score": round(
                float(np.mean([v.risk_score for v in scored])) if scored else 0.0, 4
            ),
            "metrics":     self.metrics,
            "duration_s":  round(self.duration_s, 3),
            "errors":      self.errors,
        }

    def __repr__(self) -> str:
        s = self.summary()
        return (f"Phase4Result(total={s['total']}, high_risk={s['high_risk']}, "
                f"avg_exploit_prob={s['avg_exploit_prob']})")


# ─── Phase 4 Entry Point ─────────────────────────────────────────────────────

def run_phase4(
    phase3_result,
    output_dir:  Optional[str] = None,
    verbose:     bool          = True,
) -> Phase4Result:
    """
    Run Phase 4 end-to-end.

    Args:
        phase3_result:  Phase3Result from Phase 3
        output_dir:     If set, saves models + scored_vulns.json here
        verbose:        Print progress to console

    Returns:
        Phase4Result — typed output contract consumed by Phase 5
    """
    start  = time.time()
    result = Phase4Result()

    if verbose:
        console.print()
        console.rule(
            "[bold magenta]PHASE 4 — ML Risk Scoring[/bold magenta]",
            style="magenta"
        )

    # ── Validate Phase 3 input ────────────────────────────────────────────
    if phase3_result.n_vulns == 0:
        console.print("[yellow]  No vulnerabilities to score.[/yellow]")
        result.duration_s = time.time() - start
        return result

    X     = phase3_result.X
    vulns = phase3_result.vulns

    if verbose:
        console.print(f"  Input: [cyan]{len(vulns)}[/cyan] vulnerabilities, "
                      f"[cyan]{X.shape[1]}[/cyan] features each")

    # ── Step 1: Build labeled dataset ────────────────────────────────────
    if verbose:
        console.print("  [dim]Building labeled dataset (weak labeling + augmentation)...[/dim]")

    builder = DatasetBuilder(random_state=42)
    dataset = builder.build(X, val_split=0.2, augment=True)

    if verbose:
        b = dataset.class_balance()
        console.print(
            f"  Dataset: [green]{b['n_train']}[/green] train, "
            f"[cyan]{b['n_val']}[/cyan] val | "
            f"exploitable=[red]{b['exploitable']}[/red] "
            f"benign=[green]{b['benign']}[/green]"
        )

    # ── Step 2: Train models ──────────────────────────────────────────────
    if verbose:
        console.print("  [dim]Training XGBoost classifier + RandomForest regressor...[/dim]")

    trainer = ModelTrainer()
    try:
        metrics = trainer.train(dataset)
        result.metrics = metrics
    except Exception as e:
        result.errors.append(f"Training failed: {e}")
        if verbose:
            console.print(f"[red]✗ Training error: {e}[/red]")
        result.duration_s = time.time() - start
        return result

    # ── Step 3: Save models ───────────────────────────────────────────────
    model_dir = output_dir or "./vapt_output/phase4"
    try:
        saved_paths = trainer.save(model_dir)
        result.model_dir = model_dir
    except Exception as e:
        result.errors.append(f"Model save failed: {e}")

    # ── Step 4: Score all vulnerabilities ─────────────────────────────────
    if verbose:
        console.print("  [dim]Scoring all vulnerabilities...[/dim]")

    predictor = MLPredictor.from_trainer(trainer)
    scored_vulns = predictor.score(X, list(vulns))
    result.scored_vulns = scored_vulns

    # ── Step 5: Save artifacts ────────────────────────────────────────────
    if output_dir:
        result.save(output_dir)

    result.duration_s = time.time() - start

    if verbose:
        _print_phase4_summary(result)

    return result


def _print_phase4_summary(result: Phase4Result) -> None:
    """Print rich Phase 4 summary."""
    s = result.summary()
    m = s.get("metrics", {})

    # Model metrics table
    metrics_table = Table(
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        padding=(0, 2),
    )
    metrics_table.add_column("Model",    style="cyan")
    metrics_table.add_column("Metric",   style="dim")
    metrics_table.add_column("Value",    justify="right")

    clf = m.get("classifier", {})
    if clf:
        metrics_table.add_row("XGBoost Classifier",  "Accuracy",  f"[green]{clf.get('accuracy', 0):.1%}[/green]")
        metrics_table.add_row("",                    "F1 Score",  f"{clf.get('f1_score', 0):.4f}")
        metrics_table.add_row("",                    "AUC-ROC",   f"{clf.get('auc_roc', 0):.4f}")
        metrics_table.add_row("",                    "Train time", f"{clf.get('train_time', 0)}s")

    reg = m.get("regressor", {})
    if reg:
        metrics_table.add_row("RandomForest Regressor", "MAE",      f"{reg.get('mae', 0):.4f}")
        metrics_table.add_row("",                       "R² Score", f"{reg.get('r2_score', 0):.4f}")
        metrics_table.add_row("",                       "Train time", f"{reg.get('train_time', 0)}s")

    console.print(metrics_table)

    # Top feature importances
    fi = m.get("feature_importances", {})
    if fi:
        top_features = sorted(fi.items(), key=lambda x: x[1], reverse=True)[:5]
        fi_table = Table(
            title="Top 5 Feature Importances",
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            padding=(0, 2),
        )
        fi_table.add_column("Feature",    style="cyan")
        fi_table.add_column("Importance", justify="right")

        for name, imp in top_features:
            bar = "█" * int(imp * 20)
            fi_table.add_row(name, f"[yellow]{imp:.4f}[/yellow]  {bar}")
        console.print(fi_table)

    # Scoring summary
    score_table = Table(show_header=False, border_style="dim", padding=(0, 2))
    score_table.add_column("Key",   style="dim")
    score_table.add_column("Value", style="white")
    score_table.add_row("Vulnerabilities scored", str(s["scored"]))
    score_table.add_row("High risk (≥0.7)",       f"[red]{s['high_risk']}[/red]")
    score_table.add_row("Avg exploit probability", f"{s['avg_exploit_prob']:.1%}")
    score_table.add_row("Avg risk score",          f"{s['avg_risk_score']:.4f}")
    score_table.add_row("Duration",                f"{s['duration_s']}s")
    console.print(score_table)

    console.print(
        f"\n[green]✓ Phase 4 complete[/green] "
        f"[dim]→ ScoredVulns ready for Phase 5 (Agent)[/dim]\n"
    )