"""
ml/dataset.py
─────────────
Phase 4: Training Dataset Builder.

Since we don't have a pre-labeled dataset, we use two strategies:
  1. Weak labeling — use composite_risk from Phase 3 features as proxy labels
  2. Synthetic augmentation — perturb feature vectors to expand training set

Label assignment:
  composite_risk > 0.70  →  label = 1  (exploitable)
  composite_risk < 0.30  →  label = 0  (benign / low-risk)
  0.30 <= risk <= 0.70   →  excluded   (ambiguous boundary)

Severity regression target:
  severity_score (feature index 1) used as continuous regression target
"""

from __future__ import annotations
import numpy as np
from dataclasses import dataclass
from typing import Optional

from ml.feature_extractor import FEATURE_NAMES, N_FEATURES, SEVERITY_SCORES
from rules.vuln_object import Severity

# ─── Label thresholds ────────────────────────────────────────────────────────

EXPLOIT_THRESHOLD_HIGH  = 0.70   # above → exploitable (label=1)
EXPLOIT_THRESHOLD_LOW   = 0.30   # below → benign (label=0)
NOISE_RATE              = 0.05   # 5% label flip for regularization
AUGMENTATION_FACTOR     = 4      # synthetic samples per real sample
AUGMENTATION_NOISE_STD  = 0.05   # Gaussian noise std for augmentation

# ─── Severity index in feature vector ────────────────────────────────────────
SEVERITY_FEATURE_IDX = 1   # feature index of severity_score
CVSS_FEATURE_IDX     = 0   # feature index of cwe_cvss_score
CONFIDENCE_IDX       = 2   # feature index of confidence


@dataclass
class LabeledDataset:
    """
    Output of DatasetBuilder.
    Contains feature matrix + labels for both classification and regression.
    """
    X_train:       np.ndarray   # (n_train, N_FEATURES) float32
    X_val:         np.ndarray   # (n_val,   N_FEATURES) float32
    y_clf_train:   np.ndarray   # (n_train,) int — 0 or 1 (exploit classification)
    y_clf_val:     np.ndarray   # (n_val,)   int
    y_reg_train:   np.ndarray   # (n_train,) float — severity score regression
    y_reg_val:     np.ndarray   # (n_val,)   float

    n_features:    int = N_FEATURES
    n_train:       int = 0
    n_val:         int = 0
    n_exploitable: int = 0
    n_benign:      int = 0

    def class_balance(self) -> dict:
        total = self.n_train + self.n_val
        return {
            "total":        total,
            "n_train":      self.n_train,
            "n_val":        self.n_val,
            "exploitable":  self.n_exploitable,
            "benign":       self.n_benign,
            "exploit_pct":  round(self.n_exploitable / max(total, 1) * 100, 1),
        }

    def __repr__(self) -> str:
        b = self.class_balance()
        return (f"LabeledDataset(train={self.n_train}, val={self.n_val}, "
                f"exploitable={self.n_exploitable}, benign={self.n_benign})")


class DatasetBuilder:
    """
    Builds a labeled training dataset from Phase 3 feature matrix.

    Strategy:
      1. Compute composite_risk per sample
      2. Assign weak labels based on thresholds
      3. Augment with synthetic noise to expand dataset
      4. Split into train/val (80/20 stratified)
    """

    def __init__(self, random_state: int = 42):
        self.rng = np.random.RandomState(random_state)

    def build(
        self,
        X: np.ndarray,
        val_split: float = 0.2,
        augment: bool = True,
    ) -> LabeledDataset:
        """
        Build a labeled dataset from feature matrix X.

        Args:
            X:          Feature matrix from Phase 3, shape (n, N_FEATURES)
            val_split:  Fraction of data to use for validation
            augment:    Whether to add synthetic augmented samples

        Returns:
            LabeledDataset with train/val splits
        """
        if len(X) == 0:
            return self._empty_dataset()

        # ── Step 1: Compute composite risk per sample ─────────────────────
        composite_risk = self._compute_composite_risk(X)

        # ── Step 2: Assign weak labels ────────────────────────────────────
        X_labeled, y_clf, y_reg = self._assign_labels(X, composite_risk)

        if len(X_labeled) == 0:
            # All samples in ambiguous zone — use all with noisy labels
            X_labeled = X.copy()
            y_clf = (composite_risk >= 0.5).astype(int)
            y_reg = X[:, SEVERITY_FEATURE_IDX].copy()

        # ── Step 3: Augment ───────────────────────────────────────────────
        if augment and len(X_labeled) > 0:
            X_aug, y_clf_aug, y_reg_aug = self._augment(X_labeled, y_clf, y_reg)
            X_all    = np.vstack([X_labeled, X_aug])
            y_clf_all = np.concatenate([y_clf, y_clf_aug])
            y_reg_all = np.concatenate([y_reg, y_reg_aug])
        else:
            X_all     = X_labeled
            y_clf_all = y_clf
            y_reg_all = y_reg

        # ── Step 4: Stratified train/val split ────────────────────────────
        return self._split(X_all, y_clf_all, y_reg_all, val_split)

    def _compute_composite_risk(self, X: np.ndarray) -> np.ndarray:
        """
        Compute composite risk score per sample.
        Weighted combination of key features.
        """
        weights = np.array([
            0.25,  # cwe_cvss_score
            0.25,  # severity_score
            0.10,  # confidence
            0.15,  # reachable_from_entry
            0.10,  # has_extern_input
            0.05,  # call_depth
            0.03,  # in_loop
            0.02,  # pointer_ops
            0.02,  # unsafe_api_count
            0.01,  # alloc_without_free
            0.01,  # loop_depth
            0.01,  # language_risk
        ], dtype=np.float32)

        # Ensure weights align with feature count
        if len(weights) != X.shape[1]:
            weights = np.ones(X.shape[1], dtype=np.float32) / X.shape[1]

        return (X * weights).sum(axis=1)

    def _assign_labels(
        self,
        X: np.ndarray,
        risk: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Assign binary exploit labels and regression targets.
        Excludes ambiguous samples (0.30 <= risk <= 0.70).
        """
        high_mask = risk > EXPLOIT_THRESHOLD_HIGH
        low_mask  = risk < EXPLOIT_THRESHOLD_LOW
        keep_mask = high_mask | low_mask

        X_kept    = X[keep_mask]
        y_clf     = high_mask[keep_mask].astype(np.int32)
        y_reg     = X_kept[:, SEVERITY_FEATURE_IDX].copy()

        # Add 5% label noise for regularization
        n_flip = max(1, int(len(y_clf) * NOISE_RATE))
        flip_idx = self.rng.choice(len(y_clf), size=n_flip, replace=False)
        y_clf[flip_idx] = 1 - y_clf[flip_idx]

        return X_kept, y_clf, y_reg

    def _augment(
        self,
        X: np.ndarray,
        y_clf: np.ndarray,
        y_reg: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Create synthetic samples by adding Gaussian noise to real samples.
        Binary features (0/1) are kept discrete.
        """
        BINARY_FEATURES = {3, 4, 6, 9}  # reachable, extern_input, in_loop, alloc

        n = len(X)
        X_aug_list    = []
        y_clf_aug_list = []
        y_reg_aug_list = []

        for _ in range(AUGMENTATION_FACTOR):
            noise = self.rng.normal(0, AUGMENTATION_NOISE_STD, X.shape).astype(np.float32)

            # Zero out noise for binary features
            for bi in BINARY_FEATURES:
                if bi < X.shape[1]:
                    noise[:, bi] = 0.0

            X_noisy = np.clip(X + noise, 0.0, 1.0)
            X_aug_list.append(X_noisy)
            y_clf_aug_list.append(y_clf.copy())
            y_reg_aug_list.append(y_reg.copy())

        return (
            np.vstack(X_aug_list),
            np.concatenate(y_clf_aug_list),
            np.concatenate(y_reg_aug_list),
        )

    def _split(
        self,
        X: np.ndarray,
        y_clf: np.ndarray,
        y_reg: np.ndarray,
        val_split: float,
    ) -> LabeledDataset:
        """Stratified train/val split."""
        n = len(X)

        if n < 4:
            # Too few samples — use all for training
            return LabeledDataset(
                X_train=X, X_val=X[:1],
                y_clf_train=y_clf, y_clf_val=y_clf[:1],
                y_reg_train=y_reg, y_reg_val=y_reg[:1],
                n_train=n, n_val=1,
                n_exploitable=int(y_clf.sum()),
                n_benign=int((y_clf == 0).sum()),
            )

        # Stratified split by class
        exploit_idx = np.where(y_clf == 1)[0]
        benign_idx  = np.where(y_clf == 0)[0]

        def split_idx(idx):
            n_val = max(1, int(len(idx) * val_split))
            self.rng.shuffle(idx)
            return idx[n_val:], idx[:n_val]

        train_e, val_e = split_idx(exploit_idx)
        train_b, val_b = split_idx(benign_idx)

        train_idx = np.concatenate([train_e, train_b])
        val_idx   = np.concatenate([val_e, val_b])

        self.rng.shuffle(train_idx)
        self.rng.shuffle(val_idx)

        dataset = LabeledDataset(
            X_train=X[train_idx],     X_val=X[val_idx],
            y_clf_train=y_clf[train_idx], y_clf_val=y_clf[val_idx],
            y_reg_train=y_reg[train_idx], y_reg_val=y_reg[val_idx],
            n_train=len(train_idx),   n_val=len(val_idx),
            n_exploitable=int(y_clf.sum()),
            n_benign=int((y_clf == 0).sum()),
        )
        return dataset

    def _empty_dataset(self) -> LabeledDataset:
        empty = np.zeros((0, N_FEATURES), dtype=np.float32)
        return LabeledDataset(
            X_train=empty, X_val=empty,
            y_clf_train=np.array([], dtype=np.int32),
            y_clf_val=np.array([], dtype=np.int32),
            y_reg_train=np.array([], dtype=np.float32),
            y_reg_val=np.array([], dtype=np.float32),
        )