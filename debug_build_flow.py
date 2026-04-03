"""Detailed debug of the entire dataset building flow"""
import numpy as np
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))

from core.phase1 import run_phase1
from rules.engine import run_phase2
from ml.phase3 import run_phase3
from ml.dataset import DatasetBuilder

print("=" * 80)
print("TRACING DATASET BUILD FLOW")
print("=" * 80)

samples_dir = Path(__file__).parent / "tests" / "samples"
p1 = run_phase1(str(samples_dir / "vulnerable.c"), verbose=False)
p2 = run_phase2(p1, verbose=False)
p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
X = p3.X

print(f"\nFrom Phase 3: X shape = {X.shape}, {X.shape[0]} vulnerabilities")

for strategy in ["strict", "moderate", "lenient"]:
    print(f"\n{'='*80}")
    print(f"Strategy: {strategy.upper()}")
    print(f"{'='*80}")
    
    builder = DatasetBuilder(strategy=strategy, random_state=42)
    
    # Step 1: Compute composite risk
    composite_risk = builder._compute_composite_risk(X)
    print(f"\n1. Composite risk:")
    print(f"   Min={composite_risk.min():.4f}, Max={composite_risk.max():.4f}")
    print(f"   Risk values: {composite_risk}")
    
    # Step 2: Assign labels
    X_labeled, y_clf, y_reg = builder._assign_labels(X, composite_risk)
    print(f"\n2. After _assign_labels:")
    print(f"   X_labeled shape: {X_labeled.shape}")
    print(f"   y_clf: {y_clf}")
    print(f"   Class 0 count: {(y_clf == 0).sum()}, Class 1 count: {(y_clf == 1).sum()}")
    
    # Handle empty case
    if len(X_labeled) == 0:
        print(f"   → Empty! Using fallback with 0.5 threshold")
        X_labeled = X.copy()
        y_clf = (composite_risk >= 0.5).astype(int)
        y_reg = X[:, 1].copy()
        print(f"   Fallback y_clf: {y_clf}")
        print(f"   Class 0 count: {(y_clf == 0).sum()}, Class 1 count: {(y_clf == 1).sum()}")
    
    # Step 3: Ensure class balance
    X_balanced, y_balanced, y_reg_balanced = builder._ensure_class_balance(X_labeled, y_clf.copy(), y_reg)
    print(f"\n3. After _ensure_class_balance:")
    print(f"   y_balanced: {y_balanced}")
    print(f"   Class 0 count: {(y_balanced == 0).sum()}, Class 1 count: {(y_balanced == 1).sum()}")
    
    # Step 4: Augmentation
    X_aug, y_aug, y_reg_aug = builder._augment(X_balanced, y_balanced, y_reg_balanced)
    print(f"\n4. After _augment (AUGMENTATION_FACTOR={builder._augment.__doc__}):")
    print(f"   X_aug shape: {X_aug.shape}")
    print(f"   y_aug: {y_aug}")
    print(f"   Class 0 count: {(y_aug == 0).sum()}, Class 1 count: {(y_aug == 1).sum()}")
    
    # Step 5: Oversample
    if len(X_aug) >= 20:
        X_oversampled, y_over, y_reg_over = builder._oversample_minority(X_aug, y_aug, y_reg_aug)
        print(f"\n5. After _oversample_minority:")
        print(f"   X_oversampled shape: {X_oversampled.shape}")
        print(f"   Class 0 count: {(y_over == 0).sum()}, Class 1 count: {(y_over == 1).sum()}")
    else:
        print(f"\n5. Skipped _oversample_minority (only {len(X_aug)} samples, need >= 20)")
        X_oversampled, y_over, y_reg_over = X_aug, y_aug, y_reg_aug
    
    # Step 6: Split
    dataset = builder._split(X_oversampled, y_over, y_reg_over, val_split=0.2)
    print(f"\n6. After _split:")
    print(f"   Train size: {dataset.n_train}, Val size: {dataset.n_val}")
    print(f"   y_clf_train: {dataset.y_clf_train}")
    print(f"   y_clf_val: {dataset.y_clf_val}")
    print(f"   Train Class 0 count: {(dataset.y_clf_train == 0).sum()}, Class 1 count: {(dataset.y_clf_train == 1).sum()}")
    print(f"   Val Class 0 count: {(dataset.y_clf_val == 0).sum()}, Class 1 count: {(dataset.y_clf_val == 1).sum()}")
    print(f"   Total exploitable: {dataset.n_exploitable}, Total benign: {dataset.n_benign}")

print("\n" + "=" * 80)
