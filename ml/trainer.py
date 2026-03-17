"""
ml/trainer.py
─────────────
Phase 4: ML Model Trainer.

Trains two models:
  1. XGBoost Classifier    — predicts exploit_prob (0.0–1.0)
  2. Random Forest Regressor — predicts risk_score (0.0–1.0)

Both models are trained on the labeled dataset from dataset.py.
Serialized to disk with joblib for use by predictor.py.
"""

from __future__ import annotations
import time
from pathlib import Path
from typing import Optional

import numpy as np
import joblib

from ml.feature_extractor import FEATURE_NAMES, N_FEATURES

# ─── Model hyperparameters ───────────────────────────────────────────────────
# Kept conservative to avoid overfitting on small datasets

XGB_PARAMS = {
    "n_estimators":     100,
    "max_depth":        4,
    "learning_rate":    0.1,
    "subsample":        0.8,
    "colsample_bytree": 0.8,
    "min_child_weight": 2,
    "use_label_encoder": False,
    "eval_metric":      "logloss",
    "random_state":     42,
    "verbosity":        0,
}

RF_PARAMS = {
    "n_estimators":  100,
    "max_depth":     6,
    "min_samples_leaf": 2,
    "random_state":  42,
    "n_jobs":        -1,
}


class ModelTrainer:
    """
    Trains XGBoost classifier and RandomForest regressor.

    Usage:
        trainer = ModelTrainer()
        results = trainer.train(dataset)
        trainer.save(output_dir)
    """

    def __init__(self):
        self.clf = None   # XGBoost classifier
        self.reg = None   # RandomForest regressor
        self.scaler = None
        self._train_results: dict = {}

    def train(self, dataset) -> dict:
        """
        Train both models on the labeled dataset.

        Returns:
            dict with accuracy, feature importances, and timing
        """
        from sklearn.preprocessing import StandardScaler
        from sklearn.metrics import (
            accuracy_score, f1_score, roc_auc_score,
            mean_absolute_error, r2_score
        )

        results = {}
        start = time.time()

        # ── Fit scaler on training data ───────────────────────────────────
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(dataset.X_train)
        X_val_scaled   = self.scaler.transform(dataset.X_val)

        # ── Train XGBoost Classifier ──────────────────────────────────────
        clf_start = time.time()
        self.clf = self._build_classifier(dataset)
        self.clf.fit(
            X_train_scaled, dataset.y_clf_train,
            eval_set=[(X_val_scaled, dataset.y_clf_val)],
            verbose=False,
        )

        # Evaluate classifier
        y_pred_clf  = self.clf.predict(X_val_scaled)
        y_prob_clf  = self.clf.predict_proba(X_val_scaled)[:, 1]

        clf_acc = accuracy_score(dataset.y_clf_val, y_pred_clf)
        clf_f1  = f1_score(dataset.y_clf_val, y_pred_clf, zero_division=0)

        # AUC-ROC only if both classes present in val
        try:
            clf_auc = roc_auc_score(dataset.y_clf_val, y_prob_clf)
        except ValueError:
            clf_auc = 0.5

        results["classifier"] = {
            "accuracy":   round(float(clf_acc), 4),
            "f1_score":   round(float(clf_f1), 4),
            "auc_roc":    round(float(clf_auc), 4),
            "train_time": round(time.time() - clf_start, 3),
        }

        # ── Train RandomForest Regressor ──────────────────────────────────
        reg_start = time.time()
        self.reg = self._build_regressor()
        self.reg.fit(X_train_scaled, dataset.y_reg_train)

        # Evaluate regressor
        y_pred_reg = self.reg.predict(X_val_scaled)
        reg_mae = mean_absolute_error(dataset.y_reg_val, y_pred_reg)
        reg_r2  = r2_score(dataset.y_reg_val, y_pred_reg)

        results["regressor"] = {
            "mae":        round(float(reg_mae), 4),
            "r2_score":   round(float(reg_r2), 4),
            "train_time": round(time.time() - reg_start, 3),
        }

        # ── Feature importances (from classifier) ─────────────────────────
        results["feature_importances"] = {
            name: round(float(imp), 4)
            for name, imp in zip(
                FEATURE_NAMES,
                self.clf.feature_importances_
            )
        }

        results["total_time"] = round(time.time() - start, 3)
        results["n_train"]    = dataset.n_train
        results["n_val"]      = dataset.n_val

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

    def _build_classifier(self, dataset):
        """Build XGBoost classifier with class weight balancing."""
        try:
            from xgboost import XGBClassifier
        except ImportError:
            raise RuntimeError("xgboost not installed. Run: pip install xgboost>=2.1.0")

        # Compute class weight for imbalanced data
        n_pos = max(1, dataset.n_exploitable)
        n_neg = max(1, dataset.n_benign)
        scale_pos_weight = n_neg / n_pos

        params = XGB_PARAMS.copy()
        params["scale_pos_weight"] = scale_pos_weight

        return XGBClassifier(**params)

    def _build_regressor(self):
        """Build RandomForest regressor."""
        try:
            from sklearn.ensemble import RandomForestRegressor
        except ImportError:
            raise RuntimeError("scikit-learn not installed. Run: pip install scikit-learn>=1.5.1")
        return RandomForestRegressor(**RF_PARAMS)

    @property
    def is_trained(self) -> bool:
        return self.clf is not None and self.reg is not None

    @property
    def train_results(self) -> dict:
        return self._train_results