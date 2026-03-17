"""
tests/phase3/test_phase3.py
───────────────────────────
Phase 3 test suite.
Run: pytest tests/phase3/ -v
"""

from __future__ import annotations
import pytest
import numpy as np
from pathlib import Path

SAMPLES = Path(__file__).parent.parent / "samples"


# ─── NVD Client Tests ─────────────────────────────────────────────────────────

class TestNVDClient:

    def test_offline_returns_default(self):
        from ml.nvd_client import NVDClient, CWE_CVSS_DEFAULTS
        client = NVDClient(use_api=False)
        score = client.get_cvss_score("CWE-78")
        assert score == CWE_CVSS_DEFAULTS["CWE-78"]

    def test_normalized_range(self):
        from ml.nvd_client import NVDClient
        client = NVDClient(use_api=False)
        score = client.get_cvss_normalized("CWE-78")
        assert 0.0 <= score <= 1.0

    def test_unknown_cwe_returns_default(self):
        from ml.nvd_client import NVDClient
        client = NVDClient(use_api=False)
        score = client.get_cvss_score("CWE-9999")
        assert score == 5.0

    def test_cwe_without_prefix(self):
        from ml.nvd_client import NVDClient
        client = NVDClient(use_api=False)
        score1 = client.get_cvss_score("CWE-78")
        score2 = client.get_cvss_score("78")
        assert score1 == score2

    def test_cache_works(self):
        from ml.nvd_client import NVDClient
        client = NVDClient(use_api=False)
        client.get_cvss_score("CWE-120")
        assert "CWE-120" in client._cache

    def test_prefetch(self):
        from ml.nvd_client import NVDClient
        client = NVDClient(use_api=False)
        client.prefetch(["CWE-78", "CWE-120", "CWE-416"])
        assert len(client._cache) >= 3


# ─── Feature Extractor Tests ──────────────────────────────────────────────────

class TestFeatureExtractor:

    @pytest.fixture(autouse=True)
    def setup(self):
        from core.phase1 import run_phase1
        from rules.engine import run_phase2
        from ml.nvd_client import NVDClient
        from ml.feature_extractor import FeatureExtractor

        p1 = run_phase1(str(SAMPLES / "vulnerable.c"), verbose=False)
        p2 = run_phase2(p1, verbose=False)

        nvd = NVDClient(use_api=False)
        self.extractor = FeatureExtractor(nvd)
        self.X, self.vulns = self.extractor.extract(
            p2.collection, p1.contexts, p1.call_graphs
        )

    def test_matrix_shape(self):
        from ml.feature_extractor import N_FEATURES
        assert self.X.ndim == 2
        assert self.X.shape[1] == N_FEATURES
        assert self.X.shape[0] == len(self.vulns)

    def test_no_nans(self):
        assert not np.isnan(self.X).any()

    def test_values_in_range(self):
        assert self.X.min() >= 0.0
        assert self.X.max() <= 1.0

    def test_dtype_float32(self):
        assert self.X.dtype == np.float32

    def test_synchronized_with_vulns(self):
        assert len(self.vulns) == self.X.shape[0]

    def test_feature_names_count(self):
        from ml.feature_extractor import FEATURE_NAMES, N_FEATURES
        assert len(FEATURE_NAMES) == N_FEATURES

    def test_to_dict(self):
        dicts = self.extractor.to_dict(self.X, self.vulns)
        assert len(dicts) == len(self.vulns)
        assert "vuln_id" in dicts[0]
        assert "features" in dicts[0]
        from ml.feature_extractor import N_FEATURES
        assert len(dicts[0]["features"]) == N_FEATURES

    def test_severity_feature_nonzero(self):
        # Feature index 1 is severity_score — should never be 0 for real vulns
        assert self.X[:, 1].sum() > 0

    def test_confidence_feature_nonzero(self):
        # Feature index 2 is confidence
        assert self.X[:, 2].sum() > 0


# ─── Phase 3 End-to-End ───────────────────────────────────────────────────────

class TestPhase3E2E:

    def test_full_pipeline_c(self, tmp_path):
        from core.phase1 import run_phase1
        from rules.engine import run_phase2
        from ml.phase3 import run_phase3

        p1 = run_phase1(str(SAMPLES / "vulnerable.c"), verbose=False)
        p2 = run_phase2(p1, verbose=False)
        p3 = run_phase3(p2, p1, output_dir=str(tmp_path),
                        use_nvd_api=False, verbose=False)

        assert p3.n_vulns > 0
        assert p3.X.shape == (p3.n_vulns, p3.n_features)
        assert not np.isnan(p3.X).any()

    def test_full_pipeline_all_languages(self, tmp_path):
        from core.phase1 import run_phase1
        from rules.engine import run_phase2
        from ml.phase3 import run_phase3

        p1 = run_phase1(str(SAMPLES), verbose=False)
        p2 = run_phase2(p1, verbose=False)
        p3 = run_phase3(p2, p1, output_dir=str(tmp_path),
                        use_nvd_api=False, verbose=False)

        assert p3.n_vulns > 0
        assert p3.X.shape[1] == p3.n_features

    def test_artifacts_saved(self, tmp_path):
        from core.phase1 import run_phase1
        from rules.engine import run_phase2
        from ml.phase3 import run_phase3
        import json

        p1 = run_phase1(str(SAMPLES / "vulnerable.c"), verbose=False)
        p2 = run_phase2(p1, verbose=False)
        p3 = run_phase3(p2, p1, output_dir=str(tmp_path),
                        use_nvd_api=False, verbose=False)

        features_json = tmp_path / "features.json"
        matrix_npy    = tmp_path / "feature_matrix.npy"

        assert features_json.exists()
        assert matrix_npy.exists()

        data = json.loads(features_json.read_text())
        assert "feature_names" in data
        assert "features" in data
        assert data["n_vulns"] == p3.n_vulns

        loaded_X = np.load(str(matrix_npy))
        np.testing.assert_array_equal(loaded_X, p3.X)

    def test_empty_vulns_handled(self, tmp_path):
        from core.phase1 import run_phase1
        from rules.engine import Phase2Result
        from ml.phase3 import run_phase3

        p1 = run_phase1(str(SAMPLES / "vulnerable.c"), verbose=False)
        empty_p2 = Phase2Result()  # No vulns

        p3 = run_phase3(empty_p2, p1, verbose=False)
        assert p3.n_vulns == 0

    def test_summary_keys(self, tmp_path):
        from core.phase1 import run_phase1
        from rules.engine import run_phase2
        from ml.phase3 import run_phase3

        p1 = run_phase1(str(SAMPLES / "vulnerable.c"), verbose=False)
        p2 = run_phase2(p1, verbose=False)
        p3 = run_phase3(p2, p1, verbose=False)

        s = p3.summary()
        for key in ("n_vulns", "n_features", "has_nans", "duration_s"):
            assert key in s