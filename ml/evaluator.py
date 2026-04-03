"""
ml/evaluator.py
───────────────
Model Evaluation and Cross-Validation Module.

Provides comprehensive evaluation utilities:
  1. K-fold cross-validation
  2. Confusion matrices and metrics
  3. ROC/AUC analysis
  4. Precision-Recall curves
  5. Model comparison
  6. Evaluation reporting
"""

from __future__ import annotations
import numpy as np
from typing import Optional, Literal, Tuple
from dataclasses import dataclass

from sklearn.model_selection import StratifiedKFold, cross_val_score, cross_validate
from sklearn.metrics import (
    confusion_matrix, classification_report, roc_auc_score, roc_curve,
    precision_recall_fscore_support, auc, mean_absolute_error, r2_score,
    mean_squared_error
)

from ml.feature_extractor import FEATURE_NAMES


@dataclass
class CVResult:
    """Results from K-fold cross-validation."""
    cv_scores_clf: np.ndarray      # Shape (n_splits,) - per-fold accuracies
    cv_scores_reg: np.ndarray      # Shape (n_splits,) - per-fold R2 scores
    mean_acc_clf: float
    std_acc_clf: float
    mean_r2_reg: float
    std_r2_reg: float
    fold_details: list = None

    def summary(self) -> dict:
        return {
            "classifier_mean_accuracy": round(self.mean_acc_clf, 4),
            "classifier_std_accuracy": round(self.std_acc_clf, 4),
            "regressor_mean_r2": round(self.mean_r2_reg, 4),
            "regressor_std_r2": round(self.std_r2_reg, 4),
            "n_folds": len(self.cv_scores_clf),
        }


class ModelEvaluator:
    """
    Comprehensive model evaluation utilities.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state

    def cross_validate_classifier(
        self,
        clf,
        X: np.ndarray,
        y: np.ndarray,
        n_splits: int = 5,
    ) -> CVResult:
        """
        Perform K-fold cross-validation for classifier.
        
        Args:
            clf: Trained classifier with sklearn interface
            X: Feature matrix
            y: Target labels
            n_splits: Number of folds
        
        Returns:
            CVResult with fold-by-fold and aggregate metrics
        """
        skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=self.random_state)
        
        scoring = {
            'accuracy': 'accuracy',
            'f1': 'f1',
            'roc_auc': 'roc_auc',
            'precision': 'precision',
            'recall': 'recall',
        }

        cv_results = cross_validate(
            clf, X, y, cv=skf, scoring=scoring, return_train_score=True
        )

        accuracies = cv_results['test_accuracy']
        
        return CVResult(
            cv_scores_clf=accuracies,
            cv_scores_reg=np.zeros(n_splits),  # Not applicable for classifier
            mean_acc_clf=accuracies.mean(),
            std_acc_clf=accuracies.std(),
            mean_r2_reg=0.0,
            std_r2_reg=0.0,
            fold_details=cv_results,
        )

    def cross_validate_regressor(
        self,
        reg,
        X: np.ndarray,
        y: np.ndarray,
        n_splits: int = 5,
    ) -> CVResult:
        """
        Perform K-fold cross-validation for regressor.
        
        Args:
            reg: Trained regressor with sklearn interface
            X: Feature matrix
            y: Target values
            n_splits: Number of folds
        
        Returns:
            CVResult with fold-by-fold and aggregate metrics
        """
        from sklearn.model_selection import KFold
        
        kf = KFold(n_splits=n_splits, shuffle=True, random_state=self.random_state)
        
        scoring = {
            'r2': 'r2',
            'neg_mean_absolute_error': 'neg_mean_absolute_error',
            'neg_mean_squared_error': 'neg_mean_squared_error',
        }

        cv_results = cross_validate(
            reg, X, y, cv=kf, scoring=scoring, return_train_score=True
        )

        r2_scores = cv_results['test_r2']
        
        return CVResult(
            cv_scores_clf=np.zeros(n_splits),  # Not applicable for regressor
            cv_scores_reg=r2_scores,
            mean_acc_clf=0.0,
            std_acc_clf=0.0,
            mean_r2_reg=r2_scores.mean(),
            std_r2_reg=r2_scores.std(),
            fold_details=cv_results,
        )

    def evaluate_classifier(
        self,
        clf,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> dict:
        """
        Evaluate classifier on test set with comprehensive metrics.
        """
        y_pred = clf.predict(X_test)
        y_proba = clf.predict_proba(X_test)[:, 1]

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        # Metrics
        precision, recall, f1, support = precision_recall_fscore_support(
            y_test, y_pred, average='binary', zero_division=0
        )
        
        try:
            auc_roc = roc_auc_score(y_test, y_proba)
        except ValueError:
            auc_roc = 0.5

        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        return {
            "accuracy": float((tp + tn) / (tp + tn + fp + fn)),
            "precision": float(precision),
            "recall": float(recall),
            "sensitivity": float(sensitivity),
            "specificity": float(specificity),
            "f1_score": float(f1),
            "auc_roc": float(auc_roc),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
            "confusion_matrix": cm.tolist(),
        }

    def evaluate_regressor(
        self,
        reg,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> dict:
        """
        Evaluate regressor on test set with comprehensive metrics.
        """
        y_pred = reg.predict(X_test)

        mae = mean_absolute_error(y_test, y_pred)
        mse = mean_squared_error(y_test, y_pred)
        rmse = np.sqrt(mse)
        r2 = r2_score(y_test, y_pred)
        
        # Mean Absolute Percentage Error (safe division)
        mape_values = np.abs((y_test - y_pred) / np.maximum(np.abs(y_test), 1e-10))
        mape = np.mean(mape_values) * 100

        return {
            "mae": float(mae),
            "mse": float(mse),
            "rmse": float(rmse),
            "r2_score": float(r2),
            "mape": float(mape),
        }

    def feature_importance_analysis(
        self,
        clf,
        reg,
        top_k: int = 5,
    ) -> dict:
        """
        Analyze and rank feature importances from both models.
        """
        clf_importances = clf.feature_importances_
        reg_importances = reg.feature_importances_

        # Normalize to 0-1 range
        clf_norm = clf_importances / clf_importances.sum()
        reg_norm = reg_importances / reg_importances.sum()

        # Combined importance (average)
        combined = (clf_norm + reg_norm) / 2

        # Top K
        top_indices = np.argsort(combined)[-top_k:][::-1]

        return {
            "classifier": {
                FEATURE_NAMES[i]: float(clf_norm[i])
                for i in np.argsort(clf_norm)[-top_k:][::-1]
            },
            "regressor": {
                FEATURE_NAMES[i]: float(reg_norm[i])
                for i in np.argsort(reg_norm)[-top_k:][::-1]
            },
            "combined": {
                FEATURE_NAMES[i]: float(combined[i])
                for i in top_indices
            },
            "top_features": [FEATURE_NAMES[i] for i in top_indices],
        }

    @staticmethod
    def format_classification_report(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        class_names: list = None,
    ) -> str:
        """Format sklearn classification report as string."""
        if class_names is None:
            class_names = ["Benign", "Exploitable"]
        
        return classification_report(y_true, y_pred, target_names=class_names, digits=4)


def compute_roc_curve(
    y_true: np.ndarray,
    y_proba: np.ndarray,
) -> Tuple[np.ndarray, np.ndarray, float]:
    """
    Compute ROC curve and AUC.
    
    Returns:
        Tuple of (fpr, tpr, auc_score)
    """
    try:
        fpr, tpr, _ = roc_curve(y_true, y_proba)
        auc_score = auc(fpr, tpr)
    except ValueError:
        fpr, tpr, auc_score = np.array([0, 1]), np.array([0, 1]), 0.5
    
    return fpr, tpr, auc_score


# ─────────────────────────────────────────────────────────────────────────────
# Plot helpers — dark theme, orange accent, Arial font, 10×7
# ─────────────────────────────────────────────────────────────────────────────

# Shared style constants
_BG       = "#0D1117"
_ACCENT   = "#E85D04"
_TEXT     = "#FFFFFF"
_GRID     = "#1E2A38"
_FIGSIZE  = (10, 7)
_DPI      = 150
_FONT     = "Arial"


def _apply_dark_theme(fig, ax) -> None:
    """Apply shared dark-theme cosmetics to any (fig, ax) pair."""
    import matplotlib
    matplotlib.rcParams["font.family"] = _FONT

    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_BG)

    for spine in ax.spines.values():
        spine.set_edgecolor(_GRID)

    ax.tick_params(colors=_TEXT, labelsize=11)
    ax.xaxis.label.set_color(_TEXT)
    ax.yaxis.label.set_color(_TEXT)
    ax.title.set_color(_TEXT)
    ax.grid(True, color=_GRID, linewidth=0.6, linestyle="--")


def generate_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    save_path: str,
    class_names: list[str] | None = None,
) -> str:
    """
    Save a styled confusion-matrix PNG.

    Shows TP / FP / TN / FN counts AND per-cell percentages.
    Colour intensity scales with cell count (orange palette).

    Parameters
    ----------
    y_true     : Ground-truth binary labels.
    y_pred     : Predicted binary labels.
    save_path  : Full path for the saved PNG (directories created automatically).
    class_names: Optional list of two class names.

    Returns
    -------
    Absolute path of the saved file.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.colors as mcolors
    from sklearn.metrics import confusion_matrix as sk_cm

    if class_names is None:
        class_names = ["Safe", "Vulnerable"]

    cm     = sk_cm(y_true, y_pred)
    total  = cm.sum()
    cm_pct = cm / max(total, 1) * 100

    # Build orange-shaded colormap on dark background
    cmap = mcolors.LinearSegmentedColormap.from_list(
        "vuln_cm", [_BG, "#8B2500", _ACCENT, "#FF9F4A"], N=256
    )

    fig, ax = plt.subplots(figsize=_FIGSIZE, dpi=_DPI)
    _apply_dark_theme(fig, ax)

    im = ax.imshow(cm, cmap=cmap, aspect="auto")

    # Annotate each cell
    thresh = cm.max() / 2.0
    for r in range(2):
        for c in range(2):
            count = cm[r, c]
            pct   = cm_pct[r, c]
            txt_color = _BG if count > thresh else _TEXT
            ax.text(
                c, r, f"{count}\n({pct:.1f}%)",
                ha="center", va="center",
                fontsize=14, fontweight="bold",
                color=txt_color,
            )

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(class_names, fontsize=13, color=_TEXT)
    ax.set_yticklabels(class_names, fontsize=13, color=_TEXT)
    ax.set_xlabel("Predicted Label", fontsize=13, color=_TEXT, labelpad=10)
    ax.set_ylabel("True Label",      fontsize=13, color=_TEXT, labelpad=10)
    ax.set_title("Confusion Matrix", fontsize=16, fontweight="bold",
                 color=_ACCENT, pad=15)

    # Colorbar
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.ax.yaxis.set_tick_params(color=_TEXT)
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=_TEXT)
    cbar.set_label("Count", color=_TEXT, fontsize=11)

    # TP / FP / TN / FN labels in corners
    labels_map = {(0, 0): "TN", (0, 1): "FP", (1, 0): "FN", (1, 1): "TP"}
    for (r, c), lbl in labels_map.items():
        ax.text(c + 0.42, r - 0.42, lbl, ha="right", va="top",
                fontsize=9, color=_TEXT, alpha=0.7)

    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(save_path, dpi=_DPI, bbox_inches="tight", facecolor=_BG)
    plt.close(fig)
    return str(Path(save_path).resolve())


def generate_roc_curve(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    save_path: str,
) -> str:
    """
    Save a styled AUC-ROC curve PNG.

    Displays AUC value prominently.  Random classifier dashed line shown.

    Returns
    -------
    Absolute path of the saved file.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve, auc

    fpr, tpr, _ = roc_curve(y_true, y_proba)
    roc_auc     = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=_FIGSIZE, dpi=_DPI)
    _apply_dark_theme(fig, ax)

    # Main curve
    ax.plot(fpr, tpr, color=_ACCENT, lw=2.5,
            label=f"ROC (AUC = {roc_auc:.4f})")

    # Fill area under curve
    ax.fill_between(fpr, tpr, alpha=0.18, color=_ACCENT)

    # Random classifier baseline
    ax.plot([0, 1], [0, 1], color="#555555", lw=1.5,
            linestyle="--", label="Random Classifier (AUC = 0.5)")

    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.05)
    ax.set_xlabel("False Positive Rate", fontsize=13, color=_TEXT)
    ax.set_ylabel("True Positive Rate",  fontsize=13, color=_TEXT)
    ax.set_title("Receiver Operating Characteristic (ROC)", fontsize=16,
                 fontweight="bold", color=_ACCENT)

    # Prominent AUC annotation
    ax.text(0.55, 0.15, f"AUC-ROC = {roc_auc:.4f}",
            fontsize=18, fontweight="bold", color=_ACCENT,
            transform=ax.transAxes,
            bbox=dict(boxstyle="round,pad=0.3", facecolor=_BG,
                      edgecolor=_ACCENT, alpha=0.9))

    legend = ax.legend(loc="lower right", fontsize=11, framealpha=0.3)
    for text in legend.get_texts():
        text.set_color(_TEXT)
    legend.get_frame().set_facecolor(_BG)

    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(save_path, dpi=_DPI, bbox_inches="tight", facecolor=_BG)
    plt.close(fig)
    return str(Path(save_path).resolve())


def generate_pr_curve(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    save_path: str,
) -> str:
    """
    Save a styled Precision-Recall curve PNG.

    Displays average precision prominently.  Baseline shown as dashed line.

    Returns
    -------
    Absolute path of the saved file.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import precision_recall_curve, average_precision_score

    precision, recall, _ = precision_recall_curve(y_true, y_proba)
    ap = average_precision_score(y_true, y_proba)

    no_skill = y_true.sum() / max(len(y_true), 1)

    fig, ax = plt.subplots(figsize=_FIGSIZE, dpi=_DPI)
    _apply_dark_theme(fig, ax)

    ax.plot(recall, precision, color=_ACCENT, lw=2.5,
            label=f"PR Curve (AP = {ap:.4f})")
    ax.fill_between(recall, precision, alpha=0.15, color=_ACCENT)

    ax.axhline(y=no_skill, color="#555555", lw=1.5, linestyle="--",
               label=f"No-Skill Baseline ({no_skill:.3f})")

    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.05)
    ax.set_xlabel("Recall",    fontsize=13, color=_TEXT)
    ax.set_ylabel("Precision", fontsize=13, color=_TEXT)
    ax.set_title("Precision-Recall Curve", fontsize=16,
                 fontweight="bold", color=_ACCENT)

    ax.text(0.50, 0.15, f"Avg Precision = {ap:.4f}",
            fontsize=18, fontweight="bold", color=_ACCENT,
            transform=ax.transAxes,
            bbox=dict(boxstyle="round,pad=0.3", facecolor=_BG,
                      edgecolor=_ACCENT, alpha=0.9))

    legend = ax.legend(loc="upper right", fontsize=11, framealpha=0.3)
    for text in legend.get_texts():
        text.set_color(_TEXT)
    legend.get_frame().set_facecolor(_BG)

    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(save_path, dpi=_DPI, bbox_inches="tight", facecolor=_BG)
    plt.close(fig)
    return str(Path(save_path).resolve())


def generate_feature_importance(
    model,
    feature_names: list[str],
    save_path: str,
    title: str = "XGBoost Feature Importances",
    top_n: int | None = None,
) -> str:
    """
    Save a horizontal bar chart of feature importances from an XGBoost / sklearn model.

    Bars are sorted descending by importance.  Values labelled on each bar.

    Parameters
    ----------
    model         : Trained model with `feature_importances_` attribute.
    feature_names : List of feature name strings (same order as features).
    save_path     : Full path for the saved PNG.
    title         : Chart title.
    top_n         : If set, only show top-N features.

    Returns
    -------
    Absolute path of the saved file.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    importances = np.array(model.feature_importances_)
    indices     = np.argsort(importances)[::-1]

    if top_n is not None:
        indices = indices[:top_n]

    # Reverse for horizontal bar (highest at top)
    indices   = indices[::-1]
    names     = [feature_names[i] for i in indices]
    vals      = importances[indices]

    # Normalise to 0–1 for colour mapping
    max_v = vals.max() if vals.max() > 0 else 1.0

    fig, ax = plt.subplots(figsize=_FIGSIZE, dpi=_DPI)
    _apply_dark_theme(fig, ax)

    bars = ax.barh(
        range(len(vals)), vals,
        color=[f"#{int(0x0D + (0xE8 - 0x0D) * v / max_v):02X}"
               f"{int(0x11 + (0x5D - 0x11) * v / max_v):02X}"
               f"{int(0x17 + (0x04 - 0x17) * v / max_v):02X}"
               for v in vals],
        edgecolor=_ACCENT, linewidth=0.5,
        height=0.65,
    )

    ax.set_yticks(range(len(vals)))
    ax.set_yticklabels(names, fontsize=11, color=_TEXT)
    ax.set_xlabel("Importance Score", fontsize=13, color=_TEXT)
    ax.set_title(title, fontsize=16, fontweight="bold", color=_ACCENT, pad=15)

    # Value labels on bars
    for bar, val in zip(bars, vals):
        ax.text(
            bar.get_width() + max_v * 0.01,
            bar.get_y() + bar.get_height() / 2,
            f"{val:.4f}",
            va="center", ha="left", fontsize=10, color=_TEXT,
        )

    ax.set_xlim(0, max_v * 1.18)

    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(save_path, dpi=_DPI, bbox_inches="tight", facecolor=_BG)
    plt.close(fig)
    return str(Path(save_path).resolve())

