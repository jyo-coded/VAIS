#!/usr/bin/env python3
"""
train_models.py
───────────────
Comprehensive ML Model Training Script.

Standalone script for training XGBoost and RandomForest models on vulnerability data.
Supports multiple dataset strategies, cross-validation, and detailed reporting.

Usage:
    python train_models.py --input features.json --output ./models
    python train_models.py --input feature_matrix.npy --strategy strict --cv
    python train_models.py --help
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional
import numpy as np
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ─── Local imports ────────────────────────────────────────────────────────────

try:
    from ml.dataset import DatasetBuilder, LabeledDataset
    from ml.trainer import ModelTrainer
    from ml.evaluator import ModelEvaluator
    from ml.feature_extractor import FEATURE_NAMES, N_FEATURES
except ImportError as e:
    console.print(f"[red]Error importing modules: {e}[/red]")
    console.print("[dim]Make sure you're running from the project root directory[/dim]")
    sys.exit(1)


def load_features(input_path: str) -> tuple[np.ndarray, Optional[list]]:
    """
    Load features from .npy or .json file.
    
    Returns:
        Tuple of (feature_matrix, vulnerabilities)
    """
    path = Path(input_path)
    
    if path.suffix == ".npy":
        X = np.load(path).astype(np.float32)
        return X, None
    
    elif path.suffix == ".json":
        with open(path, "r") as f:
            data = json.load(f)
        
        if isinstance(data, dict) and "features" in data:
            # VAPT format
            features_list = data["features"]
            X = np.array([f.get("vector", []) for f in features_list], dtype=np.float32)
        elif isinstance(data, list):
            # Simple list of vectors
            X = np.array(data, dtype=np.float32)
        else:
            raise ValueError("Unsupported JSON format")
        
        return X, None
    
    else:
        raise ValueError(f"Unsupported file format: {path.suffix}")


def main():
    parser = argparse.ArgumentParser(
        description="Train ML models for vulnerability assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train on existing feature matrix
  python train_models.py --input vapt_output/phase3/feature_matrix.npy \\
                         --output ./models

  # Train with strict labeling strategy and cross-validation
  python train_models.py --input features.json --strategy strict --cv \\
                         --output ./models --report report.json

  # Train with lenient strategy for more samples
  python train_models.py --input features.json --strategy lenient \\
                         --no-augment --output ./models
        """
    )

    # Input/Output
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to feature matrix (.npy or .json)",
    )
    parser.add_argument(
        "--output", "-o",
        default="./vapt_models",
        help="Output directory for models (default: ./vapt_models)",
    )
    parser.add_argument(
        "--report", "-r",
        default=None,
        help="Optional: save evaluation report to JSON file",
    )

    # Dataset and training options
    parser.add_argument(
        "--strategy",
        choices=["strict", "moderate", "lenient"],
        default="moderate",
        help="Labeling strategy (default: moderate)",
    )
    parser.add_argument(
        "--no-augment",
        action="store_true",
        help="Disable synthetic augmentation",
    )
    parser.add_argument(
        "--no-oversample",
        action="store_true",
        help="Disable minority class oversampling",
    )
    parser.add_argument(
        "--val-split",
        type=float,
        default=0.2,
        help="Validation split ratio (default: 0.2)",
    )

    # Evaluation options
    parser.add_argument(
        "--cv",
        action="store_true",
        help="Perform k-fold cross-validation",
    )
    parser.add_argument(
        "--cv-folds",
        type=int,
        default=5,
        help="Number of CV folds (default: 5)",
    )

    # Verbosity
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # ── Load features ─────────────────────────────────────────────────────
    console.print("\n[bold cyan]ML Model Training Pipeline[/bold cyan]\n")

    console.print(f"[dim]Loading features from: {args.input}[/dim]")
    try:
        X, _ = load_features(args.input)
        console.print(f"[green]✓[/green] Loaded {X.shape[0]} samples × {X.shape[1]} features")
    except Exception as e:
        console.print(f"[red]✗ Failed to load features: {e}[/red]")
        return 1

    # ── Build dataset ─────────────────────────────────────────────────────
    console.print(f"\n[dim]Building dataset with [bold]{args.strategy}[/bold] labeling strategy...[/dim]")

    builder = DatasetBuilder(random_state=42, strategy=args.strategy)
    try:
        dataset = builder.build(
            X,
            val_split=args.val_split,
            augment=not args.no_augment,
            oversample_minority=not args.no_oversample,
        )
        console.print(
            f"[green]✓[/green] Dataset built: [cyan]{dataset.n_train}[/cyan] train, "
            f"[cyan]{dataset.n_val}[/cyan] val | "
            f"exploitable=[red]{dataset.n_exploitable}[/red], "
            f"benign=[green]{dataset.n_benign}[/green]"
        )
    except Exception as e:
        console.print(f"[red]✗ Dataset building failed: {e}[/red]")
        return 1

    # ── Train models ──────────────────────────────────────────────────────
    console.print("\n[dim]Training models (XGBoost + RandomForest)...[/dim]")

    trainer = ModelTrainer()
    try:
        results = trainer.train(dataset, verbose=args.verbose)
        console.print("[green]✓[/green] Models trained successfully")

        # Display metrics
        clf_metrics = results.get("classifier", {})
        reg_metrics = results.get("regressor", {})

        table = Table(title="Model Metrics", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("XGBoost Classifier", style="green")
        table.add_column("RandomForest Regressor", style="blue")

        metrics_to_show = [
            ("Accuracy / R²", clf_metrics.get("accuracy"), reg_metrics.get("r2_score")),
            ("F1 / MAE", clf_metrics.get("f1_score"), reg_metrics.get("mae")),
            ("Precision", clf_metrics.get("precision"), "-"),
            ("Recall", clf_metrics.get("recall"), "-"),
            ("AUC-ROC", clf_metrics.get("auc_roc"), "-"),
        ]

        for label, clf_val, reg_val in metrics_to_show:
            clf_str = f"{clf_val:.4f}" if isinstance(clf_val, float) else str(clf_val)
            reg_str = f"{reg_val:.4f}" if isinstance(reg_val, float) else str(reg_val)
            table.add_row(label, clf_str, reg_str)

        console.print(table)

        # Feature importances
        console.print("\n[bold]Top Feature Importances (XGBoost Classifier)[/bold]")
        importances = results.get("feature_importances", {})
        sorted_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5]
        for feat, importance in sorted_features:
            bar_width = int(importance * 50)
            bar = "█" * bar_width + "░" * (50 - bar_width)
            console.print(f"  {feat:20s} {bar} {importance:.4f}")

    except Exception as e:
        console.print(f"[red]✗ Training failed: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    # ── Cross-validation (optional) ──────────────────────────────────────
    if args.cv:
        console.print(f"\n[dim]Performing {args.cv_folds}-fold cross-validation...[/dim]")

        evaluator = ModelEvaluator(random_state=42)
        try:
            cv_result_clf = evaluator.cross_validate_classifier(
                trainer.clf, dataset.X_train, dataset.y_clf_train, n_splits=args.cv_folds
            )
            console.print(
                f"[green]✓[/green] Classifier CV Accuracy: "
                f"{cv_result_clf.mean_acc_clf:.4f} ± {cv_result_clf.std_acc_clf:.4f}"
            )

            cv_result_reg = evaluator.cross_validate_regressor(
                trainer.reg, dataset.X_train, dataset.y_reg_train, n_splits=args.cv_folds
            )
            console.print(
                f"[green]✓[/green] Regressor CV R²: "
                f"{cv_result_reg.mean_r2_reg:.4f} ± {cv_result_reg.std_r2_reg:.4f}"
            )

            results["cross_validation"] = {
                "classifier": cv_result_clf.summary(),
                "regressor": cv_result_reg.summary(),
            }
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Cross-validation failed: {e}")

    # ── Save models ────────────────────────────────────────────────────── 
    output_dir = Path(args.output)
    console.print(f"\n[dim]Saving models to: {output_dir}[/dim]")

    try:
        saved_paths = trainer.save(output_dir)
        console.print(f"[green]✓[/green] Models saved:")
        for model_type, path in saved_paths.items():
            console.print(f"    {model_type:15s} → {path}")
    except Exception as e:
        console.print(f"[red]✗ Failed to save models: {e}[/red]")
        return 1

    # ── Save report ────────────────────────────────────────────────────
    if args.report:
        console.print(f"\n[dim]Saving report to: {args.report}[/dim]")

        report_data = {
            "dataset": {
                "n_train": dataset.n_train,
                "n_val": dataset.n_val,
                "n_exploitable": dataset.n_exploitable,
                "n_benign": dataset.n_benign,
                "exploit_ratio": dataset.n_exploitable / max(dataset.n_train + dataset.n_val, 1),
                "strategy": args.strategy,
            },
            "models": results,
            "hyperparameters": trainer.hyperparameters,
        }

        try:
            with open(args.report, "w") as f:
                json.dump(report_data, f, indent=2)
            console.print(f"[green]✓[/green] Report saved")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Failed to save report: {e}")

    console.print("\n[bold green]✓ Training completed successfully![/bold green]\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
