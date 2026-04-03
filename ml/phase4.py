"""
ml/phase4.py
────────────
Phase 4 Orchestrator — Multi-Model Ensemble Risk Scoring.

Consumes: Phase3Result (X: ndarray + vulns: List[VulnObject])
Produces: Phase4Result containing scored_vulns and ensemble metrics.

Ensemble Weights:
  - CodeBERT (Sequence Classifier): 0.50
  - GNN (Graph Neural Network)    : 0.30
  - XGBoost (Structural Features) : 0.20

Features:
  - Model loading/fallback
  - Ensemble prediction aggregation
  - Styled evaluation plots via evaluator.py
"""

from __future__ import annotations
import json
import time
import os
import warnings
from pathlib import Path
from typing import Optional, Literal

import numpy as np
from rich.console import Console
from rich.table import Table

from ml.dataset import DatasetBuilder
from ml.trainer import ModelTrainer
from ml.evaluator import (
    ModelEvaluator,
    generate_confusion_matrix,
    generate_roc_curve,
    generate_pr_curve,
    generate_feature_importance,
)
from ml.predictor import MLPredictor, score_to_severity
from rules.vuln_object import VulnObject, Severity

console = Console()
warnings.filterwarnings('ignore', category=UserWarning)


# ─── Model Paths (Constants) ──────────────────────────────────────────────────
PATH_CODEBERT = "models/codebert_vuln"
PATH_GNN      = "models/gnn_vuln.pt"
PATH_XGB      = "vapt_output/phase4"

# ─── Phase 4 Result ──────────────────────────────────────────────────────────

class Phase4Result:
    def __init__(self):
        self.scored_vulns: list[VulnObject] = []
        self.model_dir:    str              = ""
        self.metrics:      dict             = {}
        self.errors:       list[str]        = []
        self.duration_s:   float            = 0.0

    @property
    def n_vulns(self) -> int: return len(self.scored_vulns)

    def sorted_by_risk(self) -> list[VulnObject]:
        return sorted(self.scored_vulns, key=lambda v: v.composite_risk, reverse=True)

    def save(self, output_dir: str | Path) -> None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        with open(out / "scored_vulns.json", "w") as f:
            json.dump({
                "total":  self.n_vulns,
                "metrics": self.metrics,
                "vulnerabilities": [v.to_dict() for v in self.sorted_by_risk()],
            }, f, indent=2)

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
            "avg_exploit_prob": round(float(np.mean([v.exploit_prob for v in scored])) if scored else 0.0, 4),
            "avg_risk_score": round(float(np.mean([v.risk_score for v in scored])) if scored else 0.0, 4),
            "metrics":     self.metrics,
            "duration_s":  round(self.duration_s, 3),
            "errors":      self.errors,
        }


# ─── Phase 4 Entry Point ─────────────────────────────────────────────────────

def run_phase4(
    phase3_result,
    output_dir:  Optional[str] = None,
    verbose:     bool          = True,
    strategy:    Literal["strict", "moderate", "lenient"] = "moderate",
    with_evaluation: bool      = True,
) -> Phase4Result:
    start  = time.time()
    result = Phase4Result()

    if verbose:
        console.print()
        console.rule("[bold magenta]PHASE 4 — ML Multi-Model Ensemble Scoring[/bold magenta]", style="magenta")

    if phase3_result is None or phase3_result.n_vulns == 0:
        if verbose: console.print("[yellow]  No vulnerabilities to score.[/yellow]")
        result.duration_s = time.time() - start
        return result

    X     = phase3_result.X
    vulns = phase3_result.vulns
    out_path = Path(output_dir or "vapt_output/phase4")
    out_path.mkdir(parents=True, exist_ok=True)

    # ── 1. Initialise baseline models (XGBoost) ────────────────────────────────
    builder = DatasetBuilder(random_state=42, strategy=strategy)
    dataset = builder.build(np.nan_to_num(X, nan=0.0), val_split=0.2, augment=True)
    
    trainer = ModelTrainer()
    try:
        metrics = trainer.train(dataset, verbose=False)
        result.metrics = metrics
        xgb_predictor = MLPredictor.from_trainer(trainer)
        trainer.save(out_path)
    except Exception as e:
        result.errors.append(f"XGBoost training failed: {e}")
        xgb_predictor = None

    # ── 2. Load Deep Learning Models ───────────────────────────────────────────
    codebert_loaded = False
    gnn_loaded      = False
    
    try:
        from ml.codebert_model import CodeBERTPredictor
        cb_pred = CodeBERTPredictor.load(PATH_CODEBERT)
        codebert_loaded = cb_pred.is_loaded
    except Exception as e:
        cb_pred = None
        if verbose: console.print(f"[dim]  CodeBERT fallback absent ({e})[/dim]")

    try:
        from ml.gnn_model import GNNPredictor
        gnn_pred = GNNPredictor.load(PATH_GNN)
        gnn_loaded = gnn_pred.is_loaded
    except Exception as e:
        gnn_pred = None
        if verbose: console.print(f"[dim]  GNN fallback absent ({e})[/dim]")

    if verbose:
        console.print(f"  [green]✓[/green] XGBoost Ready")
        console.print(f"  [{'green' if codebert_loaded else 'yellow'}]✓[/] CodeBERT Ready: {codebert_loaded}")
        console.print(f"  [{'green' if gnn_loaded else 'yellow'}]✓[/] GNN Ready: {gnn_loaded}")

    # ── 3. Ensemble Scoring Run ───────────────────────────────────────────────
    if verbose: console.print("  [dim]Scoring vulnerabilities with Ensemble...[/dim]")

    # Run XGBoost baseline baseline risk
    if xgb_predictor:
        vulns = xgb_predictor.score(X, list(vulns))

    for vuln in vulns:
        ensemble_components = []
        p_xgb = vuln.exploit_prob or 0.0
        
        # We start with XGB as fallback if deep models fail
        final_prob = p_xgb
        
        if codebert_loaded or gnn_loaded:
            # We have deep layers; recompute using formula
            p_cb = p_gnn = 0.0
            snip = vuln.code_snippet
            
            if codebert_loaded and snip:
                p_cb = cb_pred.predict(snip)
                ensemble_components.append("CodeBERT: 0.5")
            
            if gnn_loaded and snip:
                # pass raw text, GNN wrapper parses tokens natively if AST isn't dict
                p_gnn = gnn_pred.predict(snip)
                ensemble_components.append("GNN: 0.3")

            ensemble_components.append("XGB: 0.2")

            # Weighting: CodeBERT 0.5, GNN 0.3, XGBoost 0.2
            w_cb  = 0.5 if codebert_loaded else 0.0
            w_gnn = 0.3 if gnn_loaded else 0.0
            w_xgb = 0.2 if xgb_predictor else 0.0
            
            total_w = w_cb + w_gnn + w_xgb
            if total_w > 0:
                final_prob = (p_cb * w_cb + p_gnn * w_gnn + p_xgb * w_xgb) / total_w

            vuln.add_agent_note(f"Ensemble score components: [{', '.join(ensemble_components)}]")

        vuln.exploit_prob = round(final_prob, 4)
        # Update ML Severity dynamically based on ensemble output
        vuln.ml_severity = score_to_severity(vuln.exploit_prob)

    result.scored_vulns = vulns

    count_high = sum(1 for v in vulns if v.composite_risk >= 0.7)
    if verbose:
        console.print(f"  [green]✓[/green] Scored {len(vulns)} vulnerabilities ({count_high} high-risk)")

    # ── 4. Generate Performance Plots ──────────────────────────────────────────
    if with_evaluation and xgb_predictor and len(dataset.y_clf_val) >= 2:
        if verbose: console.print("  [dim]Generating evaluation plots...[/dim]")
        
        try:
            plots_dir = out_path / "plots"
            plots_dir.mkdir(exist_ok=True)
            
            X_val_scaled = trainer.scaler.transform(dataset.X_val)
            y_pred  = trainer.clf.predict(X_val_scaled)
            y_proba = trainer.clf.predict_proba(X_val_scaled)[:, 1]
            y_true  = dataset.y_clf_val

            cm_path = generate_confusion_matrix(y_true, y_pred, str(plots_dir / "confusion_matrix.png"))
            roc_path = generate_roc_curve(y_true, y_proba, str(plots_dir / "roc_curve.png"))
            pr_path  = generate_pr_curve(y_true, y_proba, str(plots_dir / "pr_curve.png"))
            
            from ml.feature_extractor import FEATURE_NAMES
            fi_path = generate_feature_importance(
                trainer.clf, FEATURE_NAMES, str(plots_dir / "feature_importance.png")
            )

            result.metrics["plots"] = {
                "confusion_matrix": cm_path,
                "roc_curve": roc_path,
                "pr_curve": pr_path,
                "feature_importance": fi_path,
            }

            if verbose: console.print(f"  [green]✓[/green] Plots saved to {plots_dir}/")

        except Exception as e:
            if verbose: console.print(f"  [yellow]⚠[/yellow] Failed to generate plots: {e}")

    if output_dir:
        result.save(output_dir)

    result.duration_s = time.time() - start
    
    if verbose:
        _print_phase4_summary(result)

    return result

def _print_phase4_summary(result: Phase4Result) -> None:
    s = result.summary()
    m = s.get("metrics", {})

    score_table = Table(show_header=False, border_style="dim", padding=(0, 2))
    score_table.add_column("Key",   style="dim")
    score_table.add_column("Value", style="white")
    score_table.add_row("Vulnerabilities scored", str(s["scored"]))
    score_table.add_row("High risk (≥0.7)",       f"[red]{s['high_risk']}[/red]")
    score_table.add_row("Avg exploit probability", f"{s['avg_exploit_prob']:.1%}")
    score_table.add_row("Duration",                f"{s['duration_s']}s")
    console.print(score_table)

    if "plots" in m:
        console.print(f"  [cyan]View analytics plots in: {Path(m['plots']['confusion_matrix']).parent}[/cyan]")

    console.print(f"\n[green]✓ Phase 4 complete[/green] [dim]→ ScoredVulns ready for Phase 5[/dim]\n")