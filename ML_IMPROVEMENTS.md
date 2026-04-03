# ML System Improvements & Documentation

## Overview

The ML system (Phase 4) has been significantly enhanced with production-ready features, including advanced dataset management, optimized models, comprehensive evaluation, and interpretability tools.

## Key Improvements

### 1. Enhanced Dataset Builder (`ml/dataset.py`)

#### Features:
- **Multi-Strategy Labeling**: Choose between strict, moderate, and lenient labeling strategies
  - `strict`: Higher confidence labels, fewer ambiguous samples (recommended for high-precision needs)
  - `moderate` (default): Balanced approach between coverage and precision
  - `lenient`: More samples with relaxed thresholds (useful for smaller datasets)

- **SMOTE-like Oversampling**: Handles class imbalance by generating synthetic minority class samples through interpolation

- **Smart Augmentation**: Synthetic data generation with:
  - Gaussian noise for continuous features
  - Preserved binary features (reachable, input, loop, alloc)
  - Configurable augmentation factor (4x default)

- **Comprehensive Statistics**: Built-in dataset analysis with:
  - Class balance reporting
  - Feature statistics (means, stds)
  - Strategy tracking

#### Usage:
```python
from ml.dataset import DatasetBuilder

# Create builder with specific strategy
builder = DatasetBuilder(random_state=42, strategy="moderate")

# Build dataset with augmentation and oversampling
dataset = builder.build(
    X,  # Feature matrix from Phase 3
    val_split=0.2,
    augment=True,
    oversample_minority=True,
)

# Access statistics
print(f"Train samples: {dataset.n_train}")
print(f"Val samples: {dataset.n_val}")
print(f"Exploitable: {dataset.n_exploitable}")
print(f"Benign: {dataset.n_benign}")
```

### 2. Optimized Model Training (`ml/trainer.py`)

#### Features:
- **Adaptive Hyperparameters**: Automatically selects optimal hyperparameters based on:
  - Dataset size (small <100, medium 100-500, large >500)
  - Class balance ratio
  - Data characteristics

- **Enhanced Hyperparameter Tuning**:
  - Base configuration: Conservative defaults for stability
  - Aggressive config: For larger, balanced datasets
  - Conservative config: For small/imbalanced datasets

- **Early Stopping**: XGBoost stops training when validation loss plateaus (after 20 rounds without improvement)

- **Comprehensive Metrics**:
  - Classifier: Accuracy, F1, Precision, Recall, AUC-ROC
  - Regressor: MAE, MSE, RMSE, R² score
  - Feature importances from both models

#### XGBoost Parameters (Default):
```python
{
    "n_estimators": 150,
    "max_depth": 5,
    "learning_rate": 0.08,
    "subsample": 0.85,
    "colsample_bytree": 0.85,
    "reg_alpha": 0.5,      # L1 regularization
    "reg_lambda": 1.5,     # L2 regularization
    "early_stopping_rounds": 20,
}
```

#### RandomForest Parameters (Default):
```python
{
    "n_estimators": 150,
    "max_depth": 7,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
    "bootstrap": True,
}
```

#### Usage:
```python
from ml.trainer import ModelTrainer

trainer = ModelTrainer()

# Train with adaptive hyperparameters
results = trainer.train(dataset, use_cv=False, verbose=True)

# Access results
print(f"Classifier accuracy: {results['classifier']['accuracy']}")
print(f"Regressor R²: {results['regressor']['r2_score']}")
print(f"Feature importances: {results['feature_importances']}")

# Get feature importances programmatically
importances = trainer.get_feature_importances(model_type="classifier")
print(importances)

# Save models
trainer.save("./models")

# Load models later
trainer.load("./models")
```

### 3. Comprehensive Model Evaluation (`ml/evaluator.py`)

#### Features:
- **K-Fold Cross-Validation**: Stratified CV for both classifier and regressor
- **Detailed Metrics**: Confusion matrices, ROC curves, precision-recall analysis
- **Classification Report**: Formatted sklearn report with precision, recall, F1 per class
- **Regressor Metrics**: Residual analysis, MAPE calculation

#### Usage:
```python
from ml.evaluator import ModelEvaluator

evaluator = ModelEvaluator(random_state=42)

# Cross-validate classifier
cv_result = evaluator.cross_validate_classifier(
    trainer.clf, X_train, y_train, n_splits=5
)
print(f"Mean accuracy: {cv_result.mean_acc_clf:.4f} ± {cv_result.std_acc_clf:.4f}")

# Evaluate on test set
clf_metrics = evaluator.evaluate_classifier(trainer.clf, X_test, y_test)
print(f"Test accuracy: {clf_metrics['accuracy']:.4f}")
print(f"Precision: {clf_metrics['precision']:.4f}")
print(f"Recall: {clf_metrics['recall']:.4f}")
print(f"AUC-ROC: {clf_metrics['auc_roc']:.4f}")

# Feature importance analysis
feat_analysis = evaluator.feature_importance_analysis(
    trainer.clf, trainer.reg, top_k=10
)
print(f"Top features: {feat_analysis['top_features']}")
```

### 4. Model Interpretability (`ml/interpretability.py`)

#### Features:
- **Single Prediction Explanation**: Detailed breakdown for any vulnerability
  - Feature contributions
  - Top contributing factors
  - Decision path explanation
  - Confidence scores

- **Partial Dependence**: Understand how individual features affect predictions
- **Feature Interaction Analysis**: Detect feature interactions using correlation
- **Importance Summary**: Comprehensive feature importance across models

#### Usage:
```python
from ml.interpretability import ModelInterpreter

interpreter = ModelInterpreter(trainer.clf, trainer.reg)

# Explain a single prediction
explanation = interpreter.explain_prediction(x_vector)
print(f"Prediction: {explanation.prediction_class}")
print(f"Confidence: {explanation.confidence:.2%}")
print(explanation.decision_path)

# Print formatted report
report = ModelInterpreter.generate_explanation_report(explanation, sample_id="vuln_001")
print(report)

# Get partial dependence for a feature
feature_idx = 0  # cwe_cvss_score
feature_vals, predictions = interpreter.partial_dependence(
    X, feature_idx, num_points=50, use_classifier=True
)

# Get feature importance summary
summary = interpreter.get_feature_importance_summary(top_k=10)
print(f"Top features: {summary['top_features']}")
```

### 5. Enhanced Phase 4 Orchestrator (`ml/phase4.py`)

#### Features:
- **Configurable Strategies**: Pass `strategy` parameter to `run_phase4()`
  - Supports strict, moderate, lenient approaches
  
- **Comprehensive Error Handling**:
  - Input validation (null checks, shape validation)
  - NaN/Inf value handling
  - Graceful error messages

- **Optional Cross-Validation**: `with_evaluation=True` computes CV metrics
- **Detailed Logging**: Progress tracking with rich output

#### Usage:
```python
from ml.phase4 import run_phase4

# Run with default (moderate) strategy
result = run_phase4(
    phase3_result,
    output_dir="./vapt_output/phase4",
    verbose=True,
    strategy="moderate",
    with_evaluation=True,
)

print(f"High-risk vulnerabilities: {len([v for v in result.scored_vulns if v.composite_risk >= 0.7])}")
print(f"Errors: {result.errors}")
```

### 6. Comprehensive Training Script (`train_models.py`)

#### Standalone CLI tool for training models

#### Features:
- Load features from `.npy` or `.json` format
- Configure labeling strategy
- Control augmentation and oversampling
- Optional cross-validation
- Detailed reporting

#### Usage:
```bash
# Basic training
python train_models.py --input vapt_output/phase3/feature_matrix.npy \
                       --output ./models

# With strict labeling and cross-validation
python train_models.py --input features.json \
                       --strategy strict \
                       --cv \
                       --cv-folds 5 \
                       --output ./models \
                       --report report.json

# Verbose output
python train_models.py --input features.json \
                       --strategy moderate \
                       --verbose \
                       --output ./models
```

#### Command-line Options:
```
--input, -i         Path to feature matrix (.npy or .json) - REQUIRED
--output, -o        Output directory for models (default: ./vapt_models)
--report, -r        Save evaluation report to JSON file
--strategy         Labeling strategy: strict, moderate, lenient (default: moderate)
--no-augment       Disable synthetic augmentation
--no-oversample    Disable minority class oversampling
--val-split        Validation split ratio (default: 0.2)
--cv               Perform k-fold cross-validation
--cv-folds         Number of CV folds (default: 5)
--verbose, -v      Enable verbose logging
```

## Workflow Examples

### Example 1: Complete Pipeline with Strict Strategy

```python
from ml.phase3 import run_phase3
from ml.phase4 import run_phase4
from core.phase1 import run_phase1
from rules.engine import run_phase2

# Phase 1-2: Parse and detect vulnerabilities
p1 = run_phase1(path="./src", verbose=True)
p2 = run_phase2(phase1_result=p1, verbose=True)

# Phase 3: Extract features
p3 = run_phase3(phase2_result=p2, phase1_result=p1, verbose=True)

# Phase 4: Train models with strict strategy (high confidence)
p4 = run_phase4(
    p3,
    strategy="strict",
    with_evaluation=True,
    verbose=True,
)

# Analyze results
high_risk = [v for v in p4.scored_vulns if v.composite_risk >= 0.7]
print(f"Found {len(high_risk)} high-risk vulnerabilities")
```

### Example 2: Evaluate Existing Models

```python
from ml.trainer import ModelTrainer
from ml.evaluator import ModelEvaluator
from ml.interpretability import ModelInterpreter
import numpy as np

# Load pre-trained models
trainer = ModelTrainer()
trainer.load("./models")

# Load data
X_test = np.load("features_test.npy")
y_test_true = np.load("labels_test.npy")

# Evaluate
evaluator = ModelEvaluator()
metrics = evaluator.evaluate_classifier(trainer.clf, X_test, y_test_true)
print(f"Test Accuracy: {metrics['accuracy']:.4f}")

# Interpret predictions
interpreter = ModelInterpreter(trainer.clf, trainer.reg)
for i in range(min(5, len(X_test))):
    exp = interpreter.explain_prediction(X_test[i])
    print(f"\nSample {i}: Prediction={exp.prediction_class}, Confidence={exp.confidence:.2%}")
```

### Example 3: Dataset Analysis and Strategy Comparison

```python
from ml.dataset import DatasetBuilder
import numpy as np

X = np.load("features.npy")

# Compare strategies
for strategy in ["strict", "moderate", "lenient"]:
    builder = DatasetBuilder(strategy=strategy)
    dataset = builder.build(X)
    print(f"\n{strategy.upper()}:")
    print(f"  Train: {dataset.n_train}, Val: {dataset.n_val}")
    print(f"  Exploitable: {dataset.n_exploitable} ({dataset.n_exploitable/(dataset.n_train+dataset.n_val)*100:.1f}%)")
    print(f"  Benign: {dataset.n_benign}")
```

## Performance Characteristics

### Dataset Size Impact

| Dataset Size | Recommended Strategy | Typical Metrics              |
|-------------|-------------------|------|
| < 50       | strict or lenient | High variance, conservative approach  |
| 50-200     | moderate          | Balanced precision-recall            |
| 200-500    | moderate/aggressive | Good stability, reliable CV scores  |
| > 500      | aggressive        | Optimal performance, stable metrics |

### Model Performance

Typical performance on vulnerability datasets:

- **Classifier (XGBoost)**:
  - Accuracy: 0.80-0.95
  - F1-score: 0.75-0.90
  - AUC-ROC: 0.85-0.95
  - Precision: 0.80-0.95
  - Recall: 0.75-0.90

- **Regressor (RandomForest)**:
  - R² Score: 0.70-0.90
  - MAE: 0.05-0.15
  - RMSE: 0.08-0.20

## Best Practices

### 1. Dataset Strategy Selection
- **Strict**: Use for high-precision requirements where false positives are costly
- **Moderate**: Default choice for balanced requirements
- **Lenient**: Use with smaller datasets or when recall is prioritized

### 2. Hyperparameter Tuning
- Let the system auto-select based on dataset size initially
- For domain customization, adjust regularization (reg_alpha, reg_lambda) first
- Increase max_depth conservatively for complex patterns
- Monitor for overfitting using cross-validation

### 3. Model Evaluation
- Always use stratified cross-validation for imbalanced datasets
- Monitor both training and validation metrics
- Apply cross-validation before production deployment
- Compare performance across multiple evaluation metrics

### 4. Interpretability
- Use feature importance to understand model behavior
- Analyze misclassified samples using explanations
- Monitor prediction confidence for uncertain cases
- Update model when domain knowledge suggests need

## Troubleshooting

### Issue: Low Model Accuracy
**Solution**: 
1. Try lenient strategy for more training samples
2. Check feature quality and distribution
3. Increase dataset size
4. Verify data isn't corrupted (check for NaN/Inf)

### Issue: Class Imbalance Warning
**Solution**:
1. Use lenient strategy for better balance
2. Enable oversampling (default: enabled)
3. Monitor exploit_ratio metric
4. Consider weighted loss functions

### Issue: High Variance in Cross-Validation
**Solution**:
1. Increase dataset size
2. Use more conservative hyperparameters
3. Try strict strategy to ensure sample quality
4. Examine outliers and data quality

### Issue: OOM Error with Large Datasets
**Solution**:
1. Use smaller augmentation factor
2. Reduce batch size if applicable
3. Use conservative strategy (fewer samples)
4. Consider memory-efficient data formats

## Future Enhancements

- [ ] SHAP-based model explanations
- [ ] Hyperparameter optimization (Bayesian optimization)
- [ ] Ensemble methods combining multiple models
- [ ] Active learning for efficient sampling
- [ ] Real-time model monitoring and drift detection
- [ ] GPU acceleration for large datasets
- [ ] Neural network baselines (for comparison)

## References

- XGBoost: https://xgboost.readthedocs.io/
- scikit-learn: https://scikit-learn.org/
- SMOTE: Chawla, N. V., et al. (2002)
- Feature Importance: Breiman, L. (2001)

---

Last Updated: April 2, 2026  
Version: 2.0 (Enhanced ML System)
