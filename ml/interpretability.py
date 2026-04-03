"""
ml/interpretability.py
──────────────────────
Model Interpretability and Explanation Module.

Provides methods to understand model decisions:
  1. Feature importance analysis
  2. Partial dependence
  3. Individual prediction explanations
  4. Feature interaction analysis
  5. Decision tree simplification
"""

from __future__ import annotations
import numpy as np
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass

from ml.feature_extractor import FEATURE_NAMES, N_FEATURES


@dataclass
class PredictionExplanation:
    """Explanation for a single prediction."""
    prediction: float
    prediction_class: int  # For classifier
    feature_contributions: Dict[str, float]  # Feature name → contribution
    top_contributing_features: List[Tuple[str, float]]  # Top 5 features
    confidence: float
    decision_path: Optional[str]  # Simple description of decision


class ModelInterpreter:
    """
    Provides interpretability for trained models.
    """

    def __init__(self, classifier, regressor, feature_names: List[str] = None):
        """
        Args:
            classifier: Trained XGBoost classifier
            regressor: Trained RandomForest regressor
            feature_names: List of feature names (default: uses FEATURE_NAMES)
        """
        self.clf = classifier
        self.reg = regressor
        self.feature_names = feature_names or FEATURE_NAMES
        self.n_features = len(self.feature_names)

    def explain_prediction(
        self,
        x: np.ndarray,
        sample_index: Optional[int] = None,
    ) -> PredictionExplanation:
        """
        Explain a single prediction from both classifier and regressor.
        
        Args:
            x: Feature vector (1D array)
            sample_index: Optional index for reference
        
        Returns:
            PredictionExplanation with detailed breakdown
        """
        if len(x.shape) == 1:
            x = x.reshape(1, -1)

        # Get predictions
        clf_pred = self.clf.predict(x)[0]
        clf_proba = self.clf.predict_proba(x)[0]
        reg_pred = self.reg.predict(x)[0]

        # Compute feature importances from tree paths (simplified)
        clf_contributions = self._get_contributions(x, is_classifier=True)
        reg_contributions = self._get_contributions(x, is_classifier=False)

        # Combine contributions
        combined_contributions = {
            name: (clf_contributions.get(name, 0) + reg_contributions.get(name, 0)) / 2
            for name in self.feature_names
        }

        # Top contributing features
        top_features = sorted(
            combined_contributions.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:5]

        # Create decision explanation
        confidence = max(clf_proba)
        risk_level = "High Risk" if clf_pred == 1 else "Low Risk"
        
        decision_path = self._build_decision_path(
            x[0], clf_pred, confidence, top_features
        )

        return PredictionExplanation(
            prediction=float(reg_pred),
            prediction_class=int(clf_pred),
            feature_contributions=combined_contributions,
            top_contributing_features=top_features,
            confidence=float(confidence),
            decision_path=decision_path,
        )

    def _get_contributions(
        self,
        x: np.ndarray,
        is_classifier: bool = True,
    ) -> Dict[str, float]:
        """
        Estimate feature contributions using model feature importances.
        This is a simplified approach; SHAP would be more accurate.
        """
        model = self.clf if is_classifier else self.reg
        importances = model.feature_importances_

        # Normalize importances
        norm_importances = importances / (importances.sum() + 1e-10)

        # Weight by feature value
        contributions = {}
        for i, name in enumerate(self.feature_names):
            feat_value = x[0, i] if x.ndim > 1 else x[i]
            contrib = norm_importances[i] * feat_value
            contributions[name] = float(contrib)

        return contributions

    def _build_decision_path(
        self,
        x: np.ndarray,
        prediction: int,
        confidence: float,
        top_features: List[Tuple[str, float]],
    ) -> str:
        """
        Build a human-readable explanation of the prediction.
        """
        risk_level = "HIGH RISK" if prediction == 1 else "LOW RISK"
        confidence_pct = confidence * 100

        lines = [
            f"Classification: {risk_level}",
            f"Confidence: {confidence_pct:.1f}%",
            "Top contributing factors:",
        ]

        for feat_name, contrib in top_features[:3]:
            feat_value = x[self.feature_names.index(feat_name)]
            direction = "↑ increases" if contrib > 0 else "↓ decreases"
            lines.append(f"  • {feat_name} ({feat_value:.3f}) {direction} risk")

        return "\n".join(lines)

    def partial_dependence(
        self,
        X: np.ndarray,
        feature_idx: int,
        num_points: int = 50,
        use_classifier: bool = True,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Compute partial dependence of a feature on predictions.
        
        Args:
            X: Feature matrix
            feature_idx: Index of feature to analyze
            num_points: Number of points to evaluate
            use_classifier: Whether to use classifier (else regressor)
        
        Returns:
            Tuple of (feature_values, predicted_values)
        """
        model = self.clf if use_classifier else self.reg

        # Define feature value range
        feature_values = np.linspace(X[:, feature_idx].min(), X[:, feature_idx].max(), num_points)
        predictions = np.zeros(num_points)

        # Compute predictions for each feature value
        for i, feat_val in enumerate(feature_values):
            X_copy = X.copy()
            X_copy[:, feature_idx] = feat_val
            if use_classifier:
                predictions[i] = model.predict_proba(X_copy)[:, 1].mean()
            else:
                predictions[i] = model.predict(X_copy).mean()

        return feature_values, predictions

    def feature_interaction_matrix(
        self,
        X: np.ndarray,
        top_k: int = 5,
    ) -> np.ndarray:
        """
        Estimate feature interactions using correlation of residuals.
        
        Returns:
            (top_k, top_k) matrix of interaction strengths
        """
        # Get model predictions
        clf_pred = self.clf.predict_proba(X)[:, 1]
        reg_pred = self.reg.predict(X)

        # Get residuals for feature pairs
        top_features_idx = np.argsort(self.clf.feature_importances_)[-top_k:]

        interaction_matrix = np.zeros((top_k, top_k))

        for i, feat_i in enumerate(top_features_idx):
            for j, feat_j in enumerate(top_features_idx):
                if i != j:
                    # Product of features
                    product = X[:, feat_i] * X[:, feat_j]
                    # Correlation with prediction
                    interaction = np.corrcoef(product, clf_pred)[0, 1]
                    interaction_matrix[i, j] = abs(interaction)

        return interaction_matrix

    def get_feature_importance_summary(self, top_k: int = 10) -> Dict:
        """
        Get comprehensive feature importance summary.
        """
        clf_importances = self.clf.feature_importances_
        reg_importances = self.reg.feature_importances_

        # Normalize
        clf_norm = clf_importances / (clf_importances.sum() + 1e-10)
        reg_norm = reg_importances / (reg_importances.sum() + 1e-10)
        combined = (clf_norm + reg_norm) / 2

        # Top K
        top_indices = np.argsort(combined)[-top_k:][::-1]

        return {
            "classifier_top": {
                self.feature_names[i]: float(clf_norm[i])
                for i in np.argsort(clf_norm)[-top_k:][::-1]
            },
            "regressor_top": {
                self.feature_names[i]: float(reg_norm[i])
                for i in np.argsort(reg_norm)[-top_k:][::-1]
            },
            "combined_top": {
                self.feature_names[i]: float(combined[i])
                for i in top_indices
            },
            "top_features": [self.feature_names[i] for i in top_indices],
        }

    @staticmethod
    def generate_explanation_report(
        explanation: PredictionExplanation,
        sample_id: Optional[str] = None,
    ) -> str:
        """
        Generate formatted explanation report.
        """
        header = f"Prediction Explanation" + (f" (Sample: {sample_id})" if sample_id else "")
        lines = [
            f"\n{'='*60}",
            f"{header:^60}",
            f"{'='*60}\n",
            explanation.decision_path,
            f"\nPredicted Risk Score: {explanation.prediction:.4f}",
            f"Model Confidence: {explanation.confidence*100:.1f}%",
            "\nFeature Contributions:",
        ]

        for feat_name, contrib in explanation.top_contributing_features:
            bar_width = int(abs(contrib) * 30)
            bar = "█" * bar_width if contrib > 0 else "░" * bar_width
            lines.append(f"  {feat_name:20s} {bar:30s} {contrib:+.4f}")

        lines.append(f"\n{'='*60}\n")

        return "\n".join(lines)
