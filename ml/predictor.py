"""
ml/predictor.py
───────────────
Phase 4: ML Predictor.

Loads trained models and runs inference on Phase 3 feature matrix.
Attaches exploit_prob, risk_score, and ml_severity to each VulnObject.

Output: List[VulnObject] with ML fields populated — these are
        referred to as "ScoredVulns" from this point forward.
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional

import numpy as np
import joblib

from rules.vuln_object import VulnObject, Severity
from ml.feature_extractor import N_FEATURES

# ─── Thresholds for ML severity assignment ───────────────────────────────────
ML_SEVERITY_THRESHOLDS = {
    Severity.CRITICAL: 0.90,
    Severity.HIGH:     0.70,
    Severity.MEDIUM:   0.45,
    Severity.LOW:      0.20,
    # Below 0.20 → INFO
}


def score_to_severity(score: float) -> Severity:
    """Convert a continuous risk score (0-1) to a Severity enum."""
    if score >= ML_SEVERITY_THRESHOLDS[Severity.CRITICAL]:
        return Severity.CRITICAL
    elif score >= ML_SEVERITY_THRESHOLDS[Severity.HIGH]:
        return Severity.HIGH
    elif score >= ML_SEVERITY_THRESHOLDS[Severity.MEDIUM]:
        return Severity.MEDIUM
    elif score >= ML_SEVERITY_THRESHOLDS[Severity.LOW]:
        return Severity.LOW
    else:
        return Severity.INFO


class MLPredictor:
    """
    Runs ML inference and attaches scores to VulnObjects.

    Usage (from saved models):
        predictor = MLPredictor()
        predictor.load(model_dir)
        scored = predictor.score(X, vulns)

    Usage (from trainer directly):
        predictor = MLPredictor.from_trainer(trainer)
        scored = predictor.score(X, vulns)
    """

    def __init__(self):
        self._clf    = None
        self._reg    = None
        self._scaler = None

    @classmethod
    def from_trainer(cls, trainer) -> "MLPredictor":
        """Create predictor directly from a trained ModelTrainer."""
        p = cls()
        p._clf    = trainer.clf
        p._reg    = trainer.reg
        p._scaler = trainer.scaler
        return p

    def load(self, model_dir: str | Path) -> None:
        """Load models from disk."""
        d = Path(model_dir)
        self._clf    = joblib.load(d / "model_clf.pkl")
        self._reg    = joblib.load(d / "model_reg.pkl")
        self._scaler = joblib.load(d / "scaler.pkl")

    def score(
        self,
        X:     np.ndarray,
        vulns: list[VulnObject],
    ) -> list[VulnObject]:
        """
        Attach ML scores to VulnObjects in-place.

        Sets on each VulnObject:
          - exploit_prob:  float 0-1 (XGBoost classifier output)
          - risk_score:    float 0-1 (RandomForest regressor output)
          - ml_severity:   Severity enum (derived from risk_score)

        Returns the same list with fields populated.
        """
        if self._clf is None:
            raise RuntimeError("Models not loaded. Call load() or use from_trainer().")

        if len(vulns) == 0 or X.shape[0] == 0:
            return vulns

        X_scaled     = self._scaler.transform(X)
        exploit_prob = self._clf.predict_proba(X_scaled)[:, 1]
        risk_scores  = np.clip(self._reg.predict(X_scaled), 0.0, 1.0)

        for i, vuln in enumerate(vulns):
            vuln.exploit_prob = round(float(exploit_prob[i]), 4)
            vuln.risk_score   = round(float(risk_scores[i]), 4)
            vuln.ml_severity  = score_to_severity(vuln.risk_score)

            # Upgrade rule severity if ML says it's worse
            sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                         Severity.HIGH, Severity.CRITICAL]
            if sev_order.index(vuln.ml_severity) > sev_order.index(vuln.severity):
                vuln.add_agent_note(
                    f"ML upgraded severity: {vuln.severity.value} → {vuln.ml_severity.value} "
                    f"(risk_score={vuln.risk_score:.3f})"
                )

        return vulns

    @property
    def is_loaded(self) -> bool:
        return self._clf is not None