"""
ml/__init__.py
──────────────
ML Module - Machine Learning for Vulnerability Assessment.

Exports:
  Dataset Management:
    - DatasetBuilder: Create labeled datasets with multiple strategies
    - LabeledDataset: Dataset container

  Model Training:
    - ModelTrainer: Train XGBoost + RandomForest models
    - get_default_params: Access hyperparameters

  Model Evaluation:
    - ModelEvaluator: Comprehensive evaluation and cross-validation
    - CVResult: Cross-validation results

  Model Interpretation:
    - ModelInterpreter: Explain predictions
    - PredictionExplanation: Explanation container

  Data Access:
    - FeatureExtractor: Extract features from code
    - NVDClient: CVE data access
"""

from ml.dataset import DatasetBuilder, LabeledDataset
from ml.trainer import ModelTrainer
from ml.evaluator import ModelEvaluator, CVResult
from ml.interpretability import ModelInterpreter, PredictionExplanation
from ml.feature_extractor import FeatureExtractor, FEATURE_NAMES, N_FEATURES

__all__ = [
    # Dataset
    "DatasetBuilder",
    "LabeledDataset",
    # Training
    "ModelTrainer",
    # Evaluation
    "ModelEvaluator",
    "CVResult",
    # Interpretation
    "ModelInterpreter",
    "PredictionExplanation",
    # Features
    "FeatureExtractor",
    "FEATURE_NAMES",
    "N_FEATURES",
]

__version__ = "2.0"
__author__ = "VAPT Team"
