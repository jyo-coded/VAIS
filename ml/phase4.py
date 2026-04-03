"""
ml/phase4.py
────────────
Phase 4 Orchestrator — ML Risk & Exploitability Scoring (Enhanced).

Consumes: Phase3Result (X: ndarray + vulns: List[VulnObject])
Produces: Phase4Result containing:
          - scored_vulns: List[VulnObject] with exploit_prob + risk_score + ml_severity
          - model metrics (accuracy, F1, AUC-ROC, Precision, Recall, MAE, R2)
          - saved models: model_clf.pkl, model_reg.pkl, scaler.pkl
          - scored_vulns.json artifact
          - comprehensive metrics including cross-validation

Features:
  - Configurable labeling strategy (strict, moderate, lenient)
  - Class imbalance handling with SMOTE-like oversampling
  - Synthetic augmentation
  - Comprehensive error handling and validation
  - Detailed logging and reporting
"""

from __future__ import annotations
import json
import time
import warnings
from pathlib import Path
from typing import Optional, Literal

import numpy as np
from rich.console import Console
from rich.table import Table

from ml.dataset import DatasetBuilder
from ml.trainer import ModelTrainer
from ml.evaluator import ModelEvaluator
from ml.predictor import MLPredictor
from rules.vuln_object import VulnObject, Severity

console = Console()

# Suppress sklearn warnings in production
warnings.filterwarnings('ignore', category=UserWarning)


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
    strategy:    Literal["strict", "moderate", "lenient"] = "moderate",
    with_evaluation: bool      = True,
) -> Phase4Result:
    """
    Run Phase 4 end-to-end with comprehensive error handling.

    Args:
        phase3_result:    Phase3Result from Phase 3
        output_dir:       If set, saves models + scored_vulns.json here
        verbose:          Print progress to console
        strategy:         Labeling strategy: "strict" (fewer samples, high confidence),
                         "moderate" (balanced), "lenient" (more samples)
        with_evaluation:  Whether to compute cross-validation metrics

    Returns:
        Phase4Result — typed output contract consumed by Phase 5
    
    Raises:
        ValueError: If phase3_result is invalid or training fails critically
    """
    start  = time.time()
    result = Phase4Result()

    try:
        # ── Header and validation ─────────────────────────────────────────
        if verbose:
            console.print()
            console.rule(
                "[bold magenta]PHASE 4 — ML Risk Scoring[/bold magenta]",
                style="magenta"
            )

        # ── Validate Phase 3 input ────────────────────────────────────────
        if phase3_result is None:
            result.errors.append("phase3_result is None")
            if verbose:
                console.print("[red]✗ Invalid phase3_result[/red]")
            return result

        if phase3_result.n_vulns == 0:
            if verbose:
                console.print("[yellow]  No vulnerabilities to score.[/yellow]")
            result.duration_s = time.time() - start
            return result

        X     = phase3_result.X
        vulns = phase3_result.vulns

        # Validate feature matrix
        if X.shape[1] != 12:  # N_FEATURES
            result.errors.append(f"Invalid feature matrix shape: {X.shape}")
            if verbose:
                console.print(f"[red]✗ Expected 12 features, got {X.shape[1]}[/red]")
            return result

        # Check for NaN or Inf values
        if np.isnan(X).any() or np.isinf(X).any():
            X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
            if verbose:
                console.print("[yellow]⚠ Replaced NaN/Inf values in feature matrix[/yellow]")

        if verbose:
            console.print(
                f"  Input: [cyan]{len(vulns)}[/cyan] vulnerabilities, "
                f"[cyan]{X.shape[1]}[/cyan] features"
            )

        # ── Step 1: Build labeled dataset with specified strategy ─────────
        if verbose:
            console.print(
                f"  [dim]Building dataset with [bold]{strategy}[/bold] labeling strategy...[/dim]"
            )

        builder = DatasetBuilder(random_state=42, strategy=strategy)
        try:
            dataset = builder.build(
                X, 
                val_split=0.2, 
                augment=True,
                oversample_minority=True,
            )

            if verbose:
                b = dataset.class_balance()
                balance_ratio = b["exploit_pct"]
                balance_status = "[green]balanced[/green]" if 30 <= balance_ratio <= 70 else "[yellow]imbalanced[/yellow]"
                console.print(
                    f"  Dataset: [green]{b['n_train']}[/green] train, "
                    f"[cyan]{b['n_val']}[/cyan] val | "
                    f"exploitable=[red]{b['exploitable']}[/red] "
                    f"benign=[green]{b['benign']}[/green] ({balance_ratio:.1f}%) "
                    f"{balance_status}"
                )
        except Exception as e:
            result.errors.append(f"Dataset building failed: {str(e)}")
            if verbose:
                console.print(f"[red]✗ Dataset error: {e}[/red]")
            result.duration_s = time.time() - start
            return result

        # ── Step 2: Train models ──────────────────────────────────────────
        if verbose:
            console.print(
                "  [dim]Training XGBoost Classifier + RandomForest Regressor...[/dim]"
            )

        trainer = ModelTrainer()
        try:
            metrics = trainer.train(dataset, verbose=False)
            result.metrics = metrics

            if verbose:
                clf_metrics = metrics.get("classifier", {})
                console.print(
                    f"  [green]✓[/green] Classifier: "
                    f"Acc={clf_metrics.get('accuracy', 0):.4f} "
                    f"F1={clf_metrics.get('f1_score', 0):.4f} "
                    f"AUC={clf_metrics.get('auc_roc', 0):.4f}"
                )
                reg_metrics = metrics.get("regressor", {})
                console.print(
                    f"  [green]✓[/green] Regressor: "
                    f"R²={reg_metrics.get('r2_score', 0):.4f} "
                    f"MAE={reg_metrics.get('mae', 0):.4f}"
                )

        except Exception as e:
            result.errors.append(f"Training failed: {str(e)}")
            if verbose:
                console.print(f"[red]✗ Training error: {e}[/red]")
            result.duration_s = time.time() - start
            return result

        # ── Step 2b: Cross-validation (optional) ──────────────────────────
        if with_evaluation and dataset.n_train >= 10:
            if verbose:
                console.print("  [dim]Computing cross-validation metrics...[/dim]")

            evaluator = ModelEvaluator(random_state=42)
            try:
                cv_clf = evaluator.cross_validate_classifier(
                    trainer.clf, dataset.X_train, dataset.y_clf_train, n_splits=5
                )
                cv_reg = evaluator.cross_validate_regressor(
                    trainer.reg, dataset.X_train, dataset.y_reg_train, n_splits=5
                )

                result.metrics["cross_validation"] = {
                    "classifier": cv_clf.summary(),
                    "regressor": cv_reg.summary(),
                }

                if verbose:
                    console.print(
                        f"  [green]✓[/green] CV Classifier: "
                        f"{cv_clf.mean_acc_clf:.4f} ± {cv_clf.std_acc_clf:.4f}"
                    )
                    console.print(
                        f"  [green]✓[/green] CV Regressor: "
                        f"{cv_reg.mean_r2_reg:.4f} ± {cv_reg.std_r2_reg:.4f}"
                    )

            except Exception as e:
                if verbose:
                    console.print(f"  [yellow]⚠[/yellow] CV computation skipped: {e}")

        # ── Step 3: Save models ───────────────────────────────────────────
        model_dir = output_dir or "./vapt_output/phase4"
        try:
            saved_paths = trainer.save(model_dir)
            result.model_dir = model_dir
            if verbose:
                console.print(f"  [green]✓[/green] Models saved to {model_dir}/")
        except Exception as e:
            result.errors.append(f"Model save failed: {str(e)}")
            if verbose:
                console.print(f"  [yellow]⚠[/yellow] Model save warning: {e}")

        # ── Step 4: Score all vulnerabilities ─────────────────────────────
        if verbose:
            console.print("  [dim]Scoring all vulnerabilities...[/dim]")

        try:
            predictor = MLPredictor.from_trainer(trainer)
            scored_vulns = predictor.score(X, list(vulns))
            result.scored_vulns = scored_vulns

            if verbose:
                high_risk = sum(1 for v in scored_vulns if v.composite_risk >= 0.7)
                console.print(
                    f"  [green]✓[/green] Scored {len(scored_vulns)} vulnerabilities "
                    f"({high_risk} high-risk)"
                )

        except Exception as e:
            result.errors.append(f"Scoring failed: {str(e)}")
            if verbose:
                console.print(f"[red]✗ Scoring error: {e}[/red]")
            result.duration_s = time.time() - start
            return result

        # ── Step 5: Save artifacts ────────────────────────────────────────
        if output_dir:
            try:
                result.save(output_dir)
            except Exception as e:
                result.errors.append(f"Artifact save failed: {str(e)}")
                if verbose:
                    console.print(f"  [yellow]⚠[/yellow] Artifact save warning: {e}")

        result.duration_s = time.time() - start

        if verbose:
            _print_phase4_summary(result)

    except Exception as e:
        # Catch-all for unexpected errors
        result.errors.append(f"Unexpected error in Phase 4: {str(e)}")
        result.duration_s = time.time() - start
        if verbose:
            console.print(f"[red]✗ Unexpected error: {e}[/red]")

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