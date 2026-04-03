"""Debug _ensure_class_balance logic"""
import numpy as np
from ml.dataset import DatasetBuilder
from ml.feature_extractor import N_FEATURES

# Create dummy features that will all be labeled as exploitable
np.random.seed(42)
X = np.random.rand(12, N_FEATURES).astype(np.float32)
# Make features high-risk
X[:, 0] = np.linspace(0.7, 0.95, 12)  # cwe_cvss_score high
X[:, 1] = np.linspace(0.7, 0.95, 12)  # severity_score high
X[:, 2] = np.linspace(0.7, 0.95, 12)  # confidence high

print("=" * 80)
print("DEBUG: Testing _ensure_class_balance ()")
print("=" * 80)

builder = DatasetBuilder(strategy="strict")

# Manually call the labeling to see what happens
composite_risk = builder._compute_composite_risk(X)
print(f"\n1. Composite risk computed:")
print(f"   Min: {composite_risk.min():.4f}, Max: {composite_risk.max():.4f}")
print(f"   Values: {composite_risk[:5]}")

X_labeled, y_clf, y_reg = builder._assign_labels(X, composite_risk)
print(f"\n2. After _assign_labels (strict strategy):")
print(f"   X_labeled shape: {X_labeled.shape}")
print(f"   y_clf: {y_clf}")
print(f"   Class 0 count: {(y_clf == 0).sum()}")
print(f"   Class 1 count: {(y_clf == 1).sum()}")

print(f"\n3. Before _ensure_class_balance:")
print(f"   n_class_0: {(y_clf == 0).sum()}, n_class_1: {(y_clf == 1).sum()}")

# Now call the balance function and debug it
y_clf_copy = y_clf.copy()
n_class_0 = (y_clf_copy == 0).sum()
n_class_1 = (y_clf_copy == 1).sum()

if n_class_0 < 2 and n_class_1 > 0:
    print(f"\n   Triggering flip: need at least 2 benign, have {n_class_0}")
    risk = builder._compute_composite_risk(X_labeled)
    print(f"   Risk values: {risk}")
    
    n_to_create = 2 - n_class_0
    exploit_mask = y_clf_copy == 1
    exploit_risk = np.where(exploit_mask)[0]
    print(f"   exploit_risk indices: {exploit_risk}")
    print(f"   risk[exploit_risk]: {risk[exploit_risk]}")
    
    sorted_indices = np.argsort(risk[exploit_risk])
    print(f"   sorted_indices: {sorted_indices}")
    print(f"   Sorting by lowest risk...")
    
    sorted_exploit = exploit_risk[sorted_indices][:n_to_create]
    print(f"   sorted_exploit (to flip): {sorted_exploit}")
    
    y_clf_copy[sorted_exploit] = 0
    print(f"   After flipping: {y_clf_copy}")
    print(f"   Class 0 count: {(y_clf_copy == 0).sum()}, Class 1 count: {(y_clf_copy == 1).sum()}")

# Now call the actual function
X_balanced, y_balanced, y_reg_balanced = builder._ensure_class_balance(X_labeled, y_clf.copy(), y_reg)
print(f"\n4. After _ensure_class_balance (actual call):")
print(f"   y_balanced: {y_balanced}")
print(f"   Class 0 count: {(y_balanced == 0).sum()}")
print(f"   Class 1 count: {(y_balanced == 1).sum()}")

print("\n" + "=" * 80)
