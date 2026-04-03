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
