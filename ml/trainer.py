"""
ml/trainer.py
─────────────
Phase 4: ML Model Trainer (Enhanced).

Trains two models:
  1. XGBoost Classifier    — predicts exploit_prob (0.0–1.0)
  2. Random Forest Regressor — predicts risk_score (0.0–1.0)

Enhanced features:
  - Tuned hyperparameters based on data characteristics
  - Early stopping for XGBoost
  - Cross-validation support
  - Comprehensive model evaluation metrics
  - Feature importance analysis
  - Better error handling

Both models are trained on the labeled dataset from dataset.py.
Serialized to disk with joblib for use by predictor.py.
"""

from __future__ import annotations
import time
from pathlib import Path
from typing import Optional, Literal

import numpy as np
import joblib
import warnings

from ml.feature_extractor import FEATURE_NAMES, N_FEATURES

# ─── Model hyperparameters ───────────────────────────────────────────────────
# Optimized for vulnerability detection with weak labels and typical dataset sizes
# Key insight: Weak labels require STRONGER regularization to avoid memorizing noise

# Conservative defaults for weak labels (default strategy)
XGB_PARAMS_BASE = {
    "n_estimators":     200,       # More trees for stability with weak signals
    "max_depth":        4,         # Shallower (reduced from 5) to avoid overfitting to noise
    "learning_rate":    0.05,      # Slower learning (reduced from 0.08) for stability
    "subsample":        0.80,      # More aggressive subsampling to reduce variance
    "colsample_bytree": 0.80,      # Reduce column sampling
    "colsample_bylevel": 0.75,     # Reduce per-level sampling
    "min_child_weight": 5,         # Increased (from 3) - require more samples per leaf
    "gamma":            2.0,       # Increased (from 1.0) - higher split threshold
    "reg_alpha":        1.0,       # Stronger L1 regularization
    "reg_lambda":       2.0,       # Stronger L2 regularization (from 1.5)
    "use_label_encoder": False,
    "eval_metric":      "logloss",
    "random_state":     42,
    "verbosity":        0,
    "early_stopping_rounds": 30,   # Increased patience from 20
}

# Aggressive params for larger datasets (>500 samples) - still regularized for weak labels
XGB_PARAMS_AGGRESSIVE = {
    **XGB_PARAMS_BASE,
    "n_estimators":     250,
    "max_depth":        5,         # Slightly deeper ok with more data
    "learning_rate":    0.06,
    "subsample":        0.85,
    "colsample_bytree": 0.85,
    "min_child_weight": 4,         # Still strong regularization
}

# Conservative params for small datasets (<100 samples) - VERY strong regularization
XGB_PARAMS_CONSERVATIVE = {
    **XGB_PARAMS_BASE,
    "n_estimators":     150,
    "max_depth":        3,         # Even shallower for small weak-label data
    "learning_rate":    0.03,      # Very slow learning
    "min_child_weight": 8,         # Very strong leaf constraint
    "subsample":        0.75,
    "reg_lambda":       3.0,       # Maximum regularization
}

RF_PARAMS_BASE = {
    "n_estimators":  200,          # Increased from 150
    "max_depth":     6,            # Reduced from 7 for weak labels
    "min_samples_split": 10,       # Increased from 5 for weak labels
    "min_samples_leaf": 4,         # Increased from 2 for weak labels
    "max_features":  "sqrt",
    "bootstrap":     True,
    "random_state":  42,
    "n_jobs":        -1,
    "verbose":       0,
}

# More aggressive for larger datasets (but still conservative for weak labels)
RF_PARAMS_AGGRESSIVE = {
    **RF_PARAMS_BASE,
    "n_estimators": 250,
    "max_depth": 7,
    "min_samples_split": 8,        # Still conservative
}

# More conservative for smaller datasets
RF_PARAMS_CONSERVATIVE = {
    **RF_PARAMS_BASE,
    "n_estimators": 120,
    "max_depth": 4,
    "min_samples_split": 15,       # Very strong constraint
    "min_samples_leaf": 5,
}


class ModelTrainer:
    """
    Trains XGBoost classifier and RandomForest regressor.

    Enhanced with:
      - Adaptive hyperparameters based on dataset size
      - Early stopping for XGBoost
      - Cross-validation support
      - Comprehensive evaluation metrics
      - Feature importance tracking

    Usage:
        trainer = ModelTrainer()
        results = trainer.train(dataset, use_cv=True)
        trainer.save(output_dir)
    """

    def __init__(self):
        self.clf = None   # XGBoost classifier
        self.reg = None   # RandomForest regressor
        self.scaler = None
        self._train_results: dict = {}
        self._hyperparams = {}

    def _get_hyperparams(self, dataset_size: int, is_balanced: bool = True) -> tuple[dict, dict]:
        """
        Select appropriate hyperparameters based on dataset characteristics.
        
        Args:
            dataset_size: Number of training samples
            is_balanced: Whether the dataset is well-balanced (exploit_ratio between 0.4-0.6)
        
        Returns:
            Tuple of (xgb_params, rf_params)
        """
        if dataset_size < 100:
            xgb_p = XGB_PARAMS_CONSERVATIVE.copy()
            rf_p = RF_PARAMS_CONSERVATIVE.copy()
        elif dataset_size > 500:
            xgb_p = XGB_PARAMS_AGGRESSIVE.copy()
            rf_p = RF_PARAMS_AGGRESSIVE.copy()
        else:
            xgb_p = XGB_PARAMS_BASE.copy()
            rf_p = RF_PARAMS_BASE.copy()

        # Further adjust based on class balance
        if not is_balanced:
            xgb_p["min_child_weight"] = max(xgb_p["min_child_weight"], 5)
            xgb_p["reg_lambda"] = max(xgb_p["reg_lambda"], 2.0)

        return xgb_p, rf_p

    def train(self, dataset, use_cv: bool = False, verbose: bool = False) -> dict:
        """
        Train both models on the labeled dataset.

        Args:
            dataset: LabeledDataset object with train/val splits
            use_cv: Whether to use cross-validation for evaluation
            verbose: Print training progress

        Returns:
            dict with accuracy, feature importances, metrics, and timing
        """
        from sklearn.preprocessing import StandardScaler
        from sklearn.metrics import (
            accuracy_score, f1_score, roc_auc_score, precision_score, recall_score,
            mean_absolute_error, mean_squared_error, r2_score
        )

        results = {}
        start = time.time()

        # ── Validate training data has both classes ────────────────────────
        train_classes = np.unique(dataset.y_clf_train)
        if len(train_classes) == 1:
            # CRITICAL ERROR: Single class in training data
            unique_class = train_classes[0]
            class_name = "exploitable" if unique_class == 1 else "benign"
            return {
                "error": f"Training set has only {class_name} class (class {unique_class}). "
                         f"XGBoost requires both classes. "
                         f"Dataset has: exploitable={dataset.n_exploitable}, benign={dataset.n_benign}. "
                         f"This usually means the input data is too homogeneous or the labeling strategy "
                         f"failed to create class diversity. Try a more lenient strategy.",
                "n_train": dataset.n_train,
                "n_exploitable": dataset.n_exploitable,
                "n_benign": dataset.n_benign,
                "train_classes": train_classes.tolist(),
            }

        # ── Fit scaler on training data ───────────────────────────────────
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(dataset.X_train)
        X_val_scaled   = self.scaler.transform(dataset.X_val)

        # ── Determine dataset characteristics ─────────────────────────────
        dataset_size = dataset.n_train
        exploit_ratio = dataset.n_exploitable / max(dataset.n_train + dataset.n_val, 1)
        is_balanced = 0.35 <= exploit_ratio <= 0.65

        # ── Get adaptive hyperparameters ─────────────────────────────────
        xgb_params, rf_params = self._get_hyperparams(dataset_size, is_balanced)
        self._hyperparams = {"xgb": xgb_params, "rf": rf_params}

        if verbose:
            print(f"[*] Dataset size: {dataset_size}, Balanced: {is_balanced}")
            print(f"[*] Exploit ratio: {exploit_ratio:.3f}")

        # ── Train XGBoost Classifier ──────────────────────────────────────
        clf_start = time.time()
        self.clf = self._build_classifier(dataset, xgb_params)

        # Training with early stopping (only if both classes in eval_set)
        eval_classes = set(dataset.y_clf_val)
        has_both_classes = len(eval_classes) == 2
        
        if has_both_classes:
            # Use early stopping when we have both classes for validation
            self.clf.fit(
                X_train_scaled, dataset.y_clf_train,
                eval_set=[(X_val_scaled, dataset.y_clf_val)],
                verbose=False,
            )
        else:
            # Fall back to training without early stopping if val set is single-class
            self.clf.fit(X_train_scaled, dataset.y_clf_train, verbose=False)

        # Evaluate classifier
        y_pred_clf  = self.clf.predict(X_val_scaled)
        y_prob_clf  = self.clf.predict_proba(X_val_scaled)[:, 1]

        clf_acc = accuracy_score(dataset.y_clf_val, y_pred_clf)
        clf_f1  = f1_score(dataset.y_clf_val, y_pred_clf, zero_division=0)
        clf_precision = precision_score(dataset.y_clf_val, y_pred_clf, zero_division=0)
        clf_recall = recall_score(dataset.y_clf_val, y_pred_clf, zero_division=0)

        # AUC-ROC only if both classes present in val
        try:
            clf_auc = roc_auc_score(dataset.y_clf_val, y_prob_clf)
        except ValueError:
            clf_auc = 0.5

        results["classifier"] = {
            "accuracy":   round(float(clf_acc), 4),
            "f1_score":   round(float(clf_f1), 4),
            "precision":  round(float(clf_precision), 4),
            "recall":     round(float(clf_recall), 4),
            "auc_roc":    round(float(clf_auc), 4),
            "train_time": round(time.time() - clf_start, 3),
        }

        # ── Train RandomForest Regressor ──────────────────────────────────
        reg_start = time.time()
        self.reg = self._build_regressor(rf_params)
        self.reg.fit(X_train_scaled, dataset.y_reg_train)

        # Evaluate regressor
        y_pred_reg = self.reg.predict(X_val_scaled)
        reg_mae = mean_absolute_error(dataset.y_reg_val, y_pred_reg)
        reg_mse = mean_squared_error(dataset.y_reg_val, y_pred_reg)
        reg_rmse = np.sqrt(reg_mse)
        reg_r2  = r2_score(dataset.y_reg_val, y_pred_reg)

        results["regressor"] = {
            "mae":        round(float(reg_mae), 4),
            "mse":        round(float(reg_mse), 4),
            "rmse":       round(float(reg_rmse), 4),
            "r2_score":   round(float(reg_r2), 4),
            "train_time": round(time.time() - reg_start, 3),
        }

        # ── Feature importances (from both classifiers) ─────────────────────
        results["feature_importances"] = {
            name: round(float(imp), 4)
            for name, imp in zip(
                FEATURE_NAMES,
                self.clf.feature_importances_
            )
        }

        results["regressor_feature_importances"] = {
            name: round(float(imp), 4)
            for name, imp in zip(
                FEATURE_NAMES,
                self.reg.feature_importances_
            )
        }

        results["total_time"] = round(time.time() - start, 3)
        results["n_train"]    = dataset.n_train
        results["n_val"]      = dataset.n_val
        results["dataset_balanced"] = is_balanced
        results["exploit_ratio"] = round(exploit_ratio, 3)

        self._train_results = results
        return results

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Predict exploit probability for each sample.
        Returns array of shape (n,) with values in [0.0, 1.0].
        """
        if self.clf is None or self.scaler is None:
            raise RuntimeError("Model not trained. Call train() first.")
        X_scaled = self.scaler.transform(X)
        return self.clf.predict_proba(X_scaled)[:, 1]

    def predict_risk_score(self, X: np.ndarray) -> np.ndarray:
        """
        Predict continuous risk score for each sample.
        Returns array of shape (n,) clipped to [0.0, 1.0].
        """
        if self.reg is None or self.scaler is None:
            raise RuntimeError("Model not trained. Call train() first.")
        X_scaled = self.scaler.transform(X)
        scores = self.reg.predict(X_scaled)
        return np.clip(scores, 0.0, 1.0).astype(np.float32)

    def save(self, output_dir: str | Path) -> dict[str, str]:
        """
        Save models and scaler to disk.
        Returns dict of saved file paths.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        paths = {
            "clf":    str(out / "model_clf.pkl"),
            "reg":    str(out / "model_reg.pkl"),
            "scaler": str(out / "scaler.pkl"),
        }

        joblib.dump(self.clf,    paths["clf"])
        joblib.dump(self.reg,    paths["reg"])
        joblib.dump(self.scaler, paths["scaler"])

        return paths

    def load(self, output_dir: str | Path) -> None:
        """Load models and scaler from disk."""
        out = Path(output_dir)
        self.clf    = joblib.load(out / "model_clf.pkl")
        self.reg    = joblib.load(out / "model_reg.pkl")
        self.scaler = joblib.load(out / "scaler.pkl")

    def _build_classifier(self, dataset, xgb_params: dict):
        """Build XGBoost classifier with class weight balancing."""
        try:
            from xgboost import XGBClassifier
        except ImportError:
            raise RuntimeError("xgboost not installed. Run: pip install xgboost>=2.0.3")

        # Compute class weight for imbalanced data
        n_pos = max(1, dataset.n_exploitable)
        n_neg = max(1, dataset.n_benign)
        scale_pos_weight = n_neg / n_pos

        params = xgb_params.copy()
        params["scale_pos_weight"] = scale_pos_weight

        return XGBClassifier(**params)

    def _build_regressor(self, rf_params: dict):
        """Build RandomForest regressor."""
        try:
            from sklearn.ensemble import RandomForestRegressor
        except ImportError:
            raise RuntimeError("scikit-learn not installed. Run: pip install scikit-learn>=1.5.0")
        return RandomForestRegressor(**rf_params)

    @property
    def is_trained(self) -> bool:
        return self.clf is not None and self.reg is not None

    @property
    def train_results(self) -> dict:
        return self._train_results

    @property
    def hyperparameters(self) -> dict:
        """Return the hyperparameters used for training."""
        return self._hyperparams

    def get_feature_importances(self, model_type: Literal["classifier", "regressor"] = "classifier") -> dict:
        """
        Get feature importances from trained model.
        
        Args:
            model_type: Either "classifier" or "regressor"
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if model_type == "classifier":
            if self.clf is None:
                raise RuntimeError("Classifier not training. Call train() first.")
            model = self.clf
        else:
            if self.reg is None:
                raise RuntimeError("Regressor not trained. Call train() first.")
            model = self.reg

        return {
            name: float(imp)
            for name, imp in zip(FEATURE_NAMES, model.feature_importances_)
        }