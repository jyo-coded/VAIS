"""Test build() method end-to-end"""
import numpy as np
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))

from core.phase1 import run_phase1
from rules.engine import run_phase2
from ml.phase3 import run_phase3
from ml.dataset import DatasetBuilder

samples_dir = Path(__file__).parent / "tests" / "samples"
p1 = run_phase1(str(samples_dir / "vulnerable.c"), verbose=False)
p2 = run_phase2(p1, verbose=False)
p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
X = p3.X

print(f"Testing build() method with X shape: {X.shape}")

for strategy in ["strict", "moderate", "lenient"]:
    print(f"\n{'='*60}")
    print(f"Strategy: {strategy.upper()}")
    print(f"{'='*60}")
    
    builder = DatasetBuilder(strategy=strategy, random_state=42)
    dataset = builder.build(X, augment=True, oversample_minority=True)
    
    print(f"Final dataset:")
    print(f"  Total: {dataset.n_train + dataset.n_val}")
    print(f"  Train: {dataset.n_train}, Val: {dataset.n_val}")
    print(f"  Exploitable: {dataset.n_exploitable}, Benign: {dataset.n_benign}")
    print(f"  y_clf_train: {dataset.y_clf_train}")
    print(f"  y_clf_val: {dataset.y_clf_val}")
    print(f"  Train classes: {np.unique(dataset.y_clf_train).tolist()}")
