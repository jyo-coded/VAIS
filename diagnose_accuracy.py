#!/usr/bin/env python3
"""
diagnose_accuracy.py
────────────────────
Diagnostic script to identify and fix low XGBoost classifier accuracy.

Usage:
    python diagnose_accuracy.py

Tests:
  1. Circular dependency in weak labels
  2. Feature scaling issues
  3. Label quality and balance
  4. Model regularization effectiveness
"""

import numpy as np
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Add project to path
import sys
sys.path.insert(0, str(Path(__file__).parent))

from core.phase1 import run_phase1
from rules.engine import run_phase2
from ml.phase3 import run_phase3
from ml.dataset import DatasetBuilder
from ml.trainer import ModelTrainer
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, confusion_matrix

console = Console()

# ─── Test 1: Analyze weak labels ────────────────────────────────────────────

def test_label_quality():
    """Check if labels have signal or are just random."""
    console.print("\n[bold cyan]TEST 1: Label Quality Analysis[/bold cyan]")
    console.print("─" * 70)
    
    # Get sample data
    samples_dir = Path(__file__).parent / "tests" / "samples"
    p1 = run_phase1(str(samples_dir / "vulnerable.c"), verbose=False)
    p2 = run_phase2(p1, verbose=False)
    p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
    X = p3.X
    
    console.print(f"[dim]Training on {len(X)} samples with {X.shape[1]} features[/dim]")
    
    # Build dataset with OLD strategy (direct weights)
    builder_old = DatasetBuilder(strategy="moderate")
    old_composite = builder_old._compute_composite_risk(X)
    
    # Build dataset with NEW strategy (signal ensemble)
    builder_new = DatasetBuilder(strategy="moderate")
    
    # Compare: show statistics
    table = Table(title="Feature Statistics")
    table.add_column("Feature", style="cyan")
    table.add_column("Min", justify="right")
    table.add_column("Max", justify="right")
    table.add_column("Mean", justify="right")
    table.add_column("Std", justify="right")
    
    from ml.feature_extractor import FEATURE_NAMES
    for i, name in enumerate(FEATURE_NAMES):
        col = X[:, i]
        table.add_row(
            name,
            f"{col.min():.3f}",
            f"{col.max():.3f}",
            f"{col.mean():.3f}",
            f"{col.std():.3f}",
        )
    
    console.print(table)
    
    console.print(f"\n[yellow]Old Composite Risk - Min: {old_composite.min():.3f}, Max: {old_composite.max():.3f}, Mean: {old_composite.mean():.3f}[/yellow]")
    console.print("[dim]The new strategy is more conservative with normalization[/dim]")


# ─── Test 2: Test dataset building ──────────────────────────────────────────

def test_dataset_building():
    """Verify dataset is built correctly with good class balance."""
    console.print("\n[bold cyan]TEST 2: Dataset Building[/bold cyan]")
    console.print("─" * 70)
    
    samples_dir = Path(__file__).parent / "tests" / "samples"
    p1 = run_phase1(str(samples_dir / "vulnerable.c"), verbose=False)
    p2 = run_phase2(p1, verbose=False)
    p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
    X = p3.X
    
    for strategy in ["strict", "moderate", "lenient"]:
        builder = DatasetBuilder(strategy=strategy, random_state=42)
        dataset = builder.build(X, augment=True, oversample_minority=True)
        
        table = Table(title=f"Strategy: {strategy}")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")
        
        total = dataset.n_train + dataset.n_val
        balance = dataset.class_balance()
        
        table.add_row("Total samples", str(total))
        table.add_row("Train samples", str(dataset.n_train))
        table.add_row("Val samples", str(dataset.n_val))
        table.add_row("Exploitable", str(dataset.n_exploitable))
        table.add_row("Benign", str(dataset.n_benign))
        table.add_row("Exploit ratio", f"{balance['exploit_pct']:.1f}%")
        
        console.print(table)
        console.print()


# ─── Test 3: Train model and check accuracy ─────────────────────────────────

def test_model_accuracy():
    """Train XGBoost and show accuracy metrics."""
    console.print("\n[bold cyan]TEST 3: Model Accuracy[/bold cyan]")
    console.print("─" * 70)
    
    samples_dir = Path(__file__).parent / "tests" / "samples"
    p1 = run_phase1(str(samples_dir / "vulnerable.c"), verbose=False)
    p2 = run_phase2(p1, verbose=False)
    p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
    X = p3.X
    
    builder = DatasetBuilder(strategy="lenient", random_state=42)
    dataset = builder.build(X, augment=True, oversample_minority=True)
    
    trainer = ModelTrainer()
    metrics = trainer.train(dataset, verbose=False)
    
    # Show classifier metrics
    clf_metrics = metrics["classifier"]
    
    panel_content = f"""
[bold]XGBoost Classifier Metrics:[/bold]

  Accuracy:   {clf_metrics['accuracy']}
  F1 Score:   {clf_metrics['f1_score']}
  Precision:  {clf_metrics['precision']}
  Recall:     {clf_metrics['recall']}
  AUC-ROC:    {clf_metrics['auc_roc']}
  Train time: {clf_metrics['train_time']}s

[bold]RandomForest Regressor Metrics:[/bold]

  MAE:        {metrics['regressor']['mae']}
  RMSE:       {metrics['regressor']['rmse']}
  R² Score:   {metrics['regressor']['r2_score']}
  Train time: {metrics['regressor']['train_time']}s

[bold]Dataset Info:[/bold]

  Train size:      {metrics['n_train']}
  Val size:        {metrics['n_val']}
  Balanced:        {metrics['dataset_balanced']}
  Exploit ratio:   {metrics['exploit_ratio']}
"""
    
    console.print(Panel(panel_content, title="Training Results", expand=False))
    
    # Interpret results
    if clf_metrics['accuracy'] >= 0.75:
        console.print("[green]✓ GOOD: Accuracy is above 75% threshold[/green]")
    elif clf_metrics['accuracy'] >= 0.65:
        console.print("[yellow]⚠ FAIR: Accuracy between 65-75%[/yellow]")
    else:
        console.print("[red]✗ POOR: Accuracy below 65% (needs investigation)[/red]")
    
    if clf_metrics['f1_score'] > 0 and clf_metrics['f1_score'] > clf_metrics['accuracy'] * 0.8:
        console.print("[green]✓ GOOD: F1 score is balanced with accuracy[/green]")
    else:
        console.print("[yellow]⚠ UNBALANCED: F1 score suggests class imbalance issues[/yellow]")


# ─── Test 4: Feature importance ────────────────────────────────────────────

def test_feature_importance():
    """Show which features matter most for predictions."""
    console.print("\n[bold cyan]TEST 4: Feature Importance[/bold cyan]")
    console.print("─" * 70)
    
    samples_dir = Path(__file__).parent / "tests" / "samples"
    p1 = run_phase1(str(samples_dir / "vulnerable.c"), verbose=False)
    p2 = run_phase2(p1, verbose=False)
    p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
    X = p3.X
    
    builder = DatasetBuilder(strategy="lenient", random_state=42)
    dataset = builder.build(X, augment=True, oversample_minority=True)
    
    trainer = ModelTrainer()
    metrics = trainer.train(dataset, verbose=False)
    
    fi = metrics["feature_importances"]
    
    # Sort by importance
    sorted_fi = sorted(fi.items(), key=lambda x: x[1], reverse=True)
    
    table = Table(title="Feature Importances (XGBoost Classifier)")
    table.add_column("Feature", style="cyan")
    table.add_column("Importance", justify="right")
    table.add_column("Relative", justify="right")
    
    total_importance = sum(v for _, v in sorted_fi) if sorted_fi else 1.0
    max_importance = sorted_fi[0][1] if sorted_fi and sorted_fi[0][1] > 0 else 1.0
    
    for name, importance in sorted_fi[:8]:  # Top 8
        relative = (importance / max_importance) * 100 if max_importance > 0 else 0
        bar_len = int(relative / 5) if max_importance > 0 else 0
        table.add_row(
            name,
            f"{importance:.4f}",
            "█" * bar_len + f" {relative:.0f}%"
        )
    
    console.print(table)


# ─── Test 5: Cross-validation ──────────────────────────────────────────────

def test_cross_validation():
    """Test model stability with k-fold cross-validation."""
    console.print("\n[bold cyan]TEST 5: Cross-Validation Stability[/bold cyan]")
    console.print("─" * 70)
    
    from sklearn.model_selection import StratifiedKFold
    from xgboost import XGBClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import accuracy_score
    
    samples_dir = Path(__file__).parent / "tests" / "samples"
    p1 = run_phase1(str(samples_dir / "vulnerable.c"), verbose=False)
    p2 = run_phase2(p1, verbose=False)
    p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
    X = p3.X
    
    builder = DatasetBuilder(strategy="lenient", random_state=42)
    dataset = builder.build(X, augment=True, oversample_minority=True)
    
    X_all = np.vstack([dataset.X_train, dataset.X_val])
    y_all = np.concatenate([dataset.y_clf_train, dataset.y_clf_val])
    
    skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    accuracies = []
    
    for fold, (train_idx, val_idx) in enumerate(skf.split(X_all, y_all)):
        X_fold_train = X_all[train_idx]
        y_fold_train = y_all[train_idx]
        X_fold_val = X_all[val_idx]
        y_fold_val = y_all[val_idx]
        
        scaler = StandardScaler()
        X_fold_train = scaler.fit_transform(X_fold_train)
        X_fold_val = scaler.transform(X_fold_val)
        
        clf = XGBClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.05,
            reg_lambda=2.0, subsample=0.8, random_state=42, verbosity=0
        )
        clf.fit(X_fold_train, y_fold_train, verbose=False)
        
        y_pred = clf.predict(X_fold_val)
        acc = accuracy_score(y_fold_val, y_pred)
        accuracies.append(acc)
        
        console.print(f"  Fold {fold + 1}/3: {acc:.4f}")
    
    mean_acc = np.mean(accuracies)
    std_acc = np.std(accuracies)
    
    console.print(f"\n[cyan]Mean Accuracy: {mean_acc:.4f} ± {std_acc:.4f}[/cyan]")
    if std_acc < 0.1:
        console.print("[green]✓ STABLE: Low variance across folds[/green]")
    else:
        console.print("[yellow]⚠ UNSTABLE: High variance suggests overfitting[/yellow]")


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    console.print("\n")
    console.rule("[bold magenta]VAPT ML ACCURACY DIAGNOSTICS[/bold magenta]", style="magenta")
    console.print()
    
    try:
        test_label_quality()
        test_dataset_building()
        test_model_accuracy()
        test_feature_importance()
        test_cross_validation()
        
        console.print("\n")
        console.rule("[bold green]DIAGNOSTICS COMPLETE[/bold green]", style="green")
        console.print("\n[yellow]Recommendations:[/yellow]")
        console.print("  1. If accuracy is still < 65%, check feature quality in Phase 3")
        console.print("  2. Consider using 'strict' strategy for higher confidence labels")
        console.print("  3. Verify Phase 2 rules are catching real vulnerabilities")
        console.print("  4. Test with more code samples to improve model generalization")
        console.print()
        
    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
