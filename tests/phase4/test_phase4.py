"""
tests/phase4/test_phase4.py
───────────────────────────
Phase 4 test suite.
Run: pytest tests/phase4/ -v
"""

from __future__ import annotations
import pytest
import numpy as np
from pathlib import Path

SAMPLES = Path(__file__).parent.parent / "samples"


def get_phase3_result():
    """Helper: run phases 1-3 and return Phase3Result."""
    from core.phase1 import run_phase1
    from rules.engine import run_phase2
    from ml.phase3 import run_phase3

    p1 = run_phase1(str(SAMPLES / "vulnerable.c"), verbose=False)
    p2 = run_phase2(p1, verbose=False)
    p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
    return p3


# ─── Dataset Builder Tests ───────────────────────────────────────────────────

class TestDatasetBuilder:

    @pytest.fixture(autouse=True)
    def setup(self):
        from ml.dataset import DatasetBuilder
        p3 = get_phase3_result()
        self.builder = DatasetBuilder(random_state=42)
        self.dataset = self.builder.build(p3.X, val_split=0.2, augment=True)

    def test_dataset_has_samples(self):
        assert self.dataset.n_train > 0

    def test_train_val_shapes_match(self):
        assert self.dataset.X_train.shape[1] == self.dataset.X_val.shape[1]
        assert len(self.dataset.y_clf_train) == self.dataset.X_train.shape[0]
        assert len(self.dataset.y_reg_train) == self.dataset.X_train.shape[0]

    def test_labels_are_binary(self):
        unique = np.unique(self.dataset.y_clf_train)
        assert all(v in [0, 1] for v in unique)

    def test_reg_targets_in_range(self):
        assert self.dataset.y_reg_train.min() >= 0.0
        assert self.dataset.y_reg_train.max() <= 1.0

    def test_augmentation_increases_samples(self):
        from ml.dataset import DatasetBuilder
        p3 = get_phase3_result()
        builder = DatasetBuilder()
        small = builder.build(p3.X, augment=False)
        large = builder.build(p3.X, augment=True)
        assert large.n_train + large.n_val >= small.n_train + small.n_val

    def test_class_balance_summary(self):
        b = self.dataset.class_balance()
        assert "total" in b
        assert "exploitable" in b
        assert "benign" in b


# ─── Model Trainer Tests ─────────────────────────────────────────────────────

class TestModelTrainer:

    @pytest.fixture(autouse=True)
    def setup(self):
        from ml.dataset import DatasetBuilder
        from ml.trainer import ModelTrainer
        p3 = get_phase3_result()
        builder = DatasetBuilder(random_state=42)
        dataset = builder.build(p3.X, augment=True)
        self.trainer = ModelTrainer()
        self.metrics = self.trainer.train(dataset)

    def test_models_trained(self):
        assert self.trainer.is_trained

    def test_metrics_returned(self):
        assert "classifier" in self.metrics
        assert "regressor" in self.metrics

    def test_classifier_accuracy_present(self):
        assert "accuracy" in self.metrics["classifier"]
        acc = self.metrics["classifier"]["accuracy"]
        assert 0.0 <= acc <= 1.0

    def test_feature_importances_present(self):
        assert "feature_importances" in self.metrics
        fi = self.metrics["feature_importances"]
        from ml.feature_extractor import FEATURE_NAMES
        assert len(fi) == len(FEATURE_NAMES)

    def test_predict_proba_shape(self):
        p3 = get_phase3_result()
        probs = self.trainer.predict_proba(p3.X)
        assert probs.shape == (p3.n_vulns,)
        assert probs.min() >= 0.0
        assert probs.max() <= 1.0

    def test_predict_risk_shape(self):
        p3 = get_phase3_result()
        scores = self.trainer.predict_risk_score(p3.X)
        assert scores.shape == (p3.n_vulns,)
        assert scores.min() >= 0.0
        assert scores.max() <= 1.0

    def test_save_and_load(self, tmp_path):
        from ml.trainer import ModelTrainer
        paths = self.trainer.save(tmp_path)
        assert (tmp_path / "model_clf.pkl").exists()
        assert (tmp_path / "model_reg.pkl").exists()
        assert (tmp_path / "scaler.pkl").exists()

        new_trainer = ModelTrainer()
        new_trainer.load(tmp_path)
        assert new_trainer.is_trained


# ─── Predictor Tests ─────────────────────────────────────────────────────────

class TestMLPredictor:

    @pytest.fixture(autouse=True)
    def setup(self):
        from ml.dataset import DatasetBuilder
        from ml.trainer import ModelTrainer
        from ml.predictor import MLPredictor
        p3 = get_phase3_result()
        builder = DatasetBuilder(random_state=42)
        dataset = builder.build(p3.X, augment=True)
        trainer = ModelTrainer()
        trainer.train(dataset)
        self.predictor = MLPredictor.from_trainer(trainer)
        self.p3 = p3

    def test_scores_all_vulns(self):
        scored = self.predictor.score(self.p3.X, list(self.p3.vulns))
        assert len(scored) == self.p3.n_vulns

    def test_exploit_prob_attached(self):
        scored = self.predictor.score(self.p3.X, list(self.p3.vulns))
        for v in scored:
            assert v.exploit_prob is not None
            assert 0.0 <= v.exploit_prob <= 1.0

    def test_risk_score_attached(self):
        scored = self.predictor.score(self.p3.X, list(self.p3.vulns))
        for v in scored:
            assert v.risk_score is not None
            assert 0.0 <= v.risk_score <= 1.0

    def test_ml_severity_attached(self):
        from rules.vuln_object import Severity
        scored = self.predictor.score(self.p3.X, list(self.p3.vulns))
        valid_severities = set(Severity)
        for v in scored:
            assert v.ml_severity in valid_severities


# ─── Phase 4 End-to-End ──────────────────────────────────────────────────────

class TestPhase4E2E:

    def test_full_pipeline(self, tmp_path):
        from ml.phase4 import run_phase4
        p3 = get_phase3_result()
        p4 = run_phase4(p3, output_dir=str(tmp_path), verbose=False)
        assert p4.n_vulns > 0
        assert len(p4.errors) == 0

    def test_artifacts_saved(self, tmp_path):
        import json
        from ml.phase4 import run_phase4
        p3 = get_phase3_result()
        p4 = run_phase4(p3, output_dir=str(tmp_path), verbose=False)

        assert (tmp_path / "scored_vulns.json").exists()
        assert (tmp_path / "model_clf.pkl").exists()
        assert (tmp_path / "model_reg.pkl").exists()
        assert (tmp_path / "scaler.pkl").exists()

        data = json.loads((tmp_path / "scored_vulns.json").read_text())
        assert "vulnerabilities" in data
        assert data["total"] > 0

    def test_scored_vulns_sorted_by_risk(self, tmp_path):
        from ml.phase4 import run_phase4
        p3 = get_phase3_result()
        p4 = run_phase4(p3, output_dir=str(tmp_path), verbose=False)

        ranked = p4.sorted_by_risk()
        for i in range(len(ranked) - 1):
            assert ranked[i].composite_risk >= ranked[i + 1].composite_risk

    def test_summary_keys(self, tmp_path):
        from ml.phase4 import run_phase4
        p3 = get_phase3_result()
        p4 = run_phase4(p3, output_dir=str(tmp_path), verbose=False)
        s = p4.summary()
        for key in ("total", "scored", "high_risk", "avg_exploit_prob",
                    "avg_risk_score", "duration_s"):
            assert key in s

    def test_empty_input_handled(self):
        from ml.phase3 import Phase3Result
        from ml.phase4 import run_phase4
        empty_p3 = Phase3Result()
        p4 = run_phase4(empty_p3, verbose=False)
        assert p4.n_vulns == 0