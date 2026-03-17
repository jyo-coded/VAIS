"""
tests/phase6/test_phase6.py
───────────────────────────
Phase 6 test suite.
Run: pytest tests/phase6/ -v
"""

from __future__ import annotations
import json
import pytest
from pathlib import Path

SAMPLES = Path(__file__).parent.parent / "samples"


def get_phase5_result():
    """Run phases 1-5 and return Phase5Result (uses fallback agent)."""
    from core.phase1 import run_phase1
    from rules.engine import run_phase2
    from ml.phase3 import run_phase3
    from ml.phase4 import run_phase4
    from agent.phase5 import run_phase5
    from agent.ollama_agent import OllamaAgent

    p1 = run_phase1(str(SAMPLES / "vulnerable.c"), verbose=False)
    p2 = run_phase2(p1, verbose=False)
    p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
    p4 = run_phase4(p3, verbose=False)

    # Force fallback — don't wait for Ollama in tests
    p5 = run_phase5(p4, verbose=False)
    return p5


# ─── Template Library Tests ───────────────────────────────────────────────────

class TestTemplateLibrary:

    def test_get_template_exact_match(self):
        from patch.template_library import get_template
        t = get_template("CWE-120", "replace_strcpy_with_strncpy")
        assert t is not None
        assert t.strategy == "replace_strcpy_with_strncpy"

    def test_get_template_strategy_fallback(self):
        from patch.template_library import get_template
        t = get_template("CWE-999", "replace_strcpy_with_strncpy")
        assert t is not None  # strategy match

    def test_get_template_cwe_fallback(self):
        from patch.template_library import get_template
        t = get_template("CWE-120", "nonexistent_strategy")
        assert t is not None  # CWE match

    def test_get_template_no_match(self):
        from patch.template_library import get_template
        t = get_template("CWE-999", "nonexistent_strategy")
        assert t is None

    def test_strcpy_match_fn(self):
        from patch.template_library import get_template
        t = get_template("CWE-120", "replace_strcpy_with_strncpy")
        assert t.match_fn('    strcpy(dst, src);')
        assert not t.match_fn('    strncpy(dst, src, n);')

    def test_gets_match_fn(self):
        from patch.template_library import get_template
        t = get_template("CWE-120", "replace_gets_with_fgets")
        assert t.match_fn('    gets(buf);')
        assert not t.match_fn('    fgets(buf, n, stdin);')

    def test_strcpy_patch_produces_two_lines(self):
        from patch.template_library import get_template
        t = get_template("CWE-120", "replace_strcpy_with_strncpy")
        result = t.patch_fn('    strcpy(dest, src);\n', "fn", [], 0)
        assert len(result) == 2
        assert "strncpy" in result[0]
        assert "= '\\0'" in result[1]

    def test_gets_patch_produces_two_lines(self):
        from patch.template_library import get_template
        t = get_template("CWE-120", "replace_gets_with_fgets")
        result = t.patch_fn('    gets(buffer);\n', "fn", [], 0)
        assert len(result) == 2
        assert "fgets" in result[0]
        assert "strcspn" in result[1]

    def test_sprintf_patch(self):
        from patch.template_library import get_template
        t = get_template("CWE-120", "replace_sprintf_with_snprintf")
        result = t.patch_fn('    sprintf(buf, "%s", name);\n', "fn", [], 0)
        assert "snprintf" in result[0]

    def test_free_null_patch(self):
        from patch.template_library import get_template
        t = get_template("CWE-416", "set_pointer_null_after_free")
        result = t.patch_fn('    free(ptr);\n', "fn", [], 0)
        assert any("NULL" in l for l in result)

    def test_double_free_patch_has_null_check(self):
        from patch.template_library import get_template
        t = get_template("CWE-415", "add_null_check_before_free")
        result = t.patch_fn('    free(ptr);\n', "fn", [], 0)
        assert any("!= NULL" in l for l in result)


# ─── Patch Engine Tests ───────────────────────────────────────────────────────

class TestPatchEngine:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.p5 = get_phase5_result()

    def test_apply_all_returns_results(self, tmp_path):
        from patch.patch_engine import PatchEngine
        engine = PatchEngine()
        results, patched = engine.apply_all(
            self.p5.decisions, self.p5.scored_vulns, tmp_path
        )
        assert len(results) == len(self.p5.decisions)

    def test_patched_file_created(self, tmp_path):
        from patch.patch_engine import PatchEngine
        engine = PatchEngine()
        _, patched = engine.apply_all(
            self.p5.decisions, self.p5.scored_vulns, tmp_path
        )
        for _, pf in patched.items():
            assert Path(pf).exists()

    def test_diff_file_created(self, tmp_path):
        from patch.patch_engine import PatchEngine
        engine = PatchEngine()
        engine.apply_all(self.p5.decisions, self.p5.scored_vulns, tmp_path)
        diffs = list(tmp_path.glob("*.diff"))
        assert len(diffs) > 0

    def test_some_patches_succeed(self, tmp_path):
        from patch.patch_engine import PatchEngine
        engine = PatchEngine()
        results, _ = engine.apply_all(
            self.p5.decisions, self.p5.scored_vulns, tmp_path
        )
        assert any(r.success for r in results)

    def test_patch_result_has_required_fields(self, tmp_path):
        from patch.patch_engine import PatchEngine
        engine = PatchEngine()
        results, _ = engine.apply_all(
            self.p5.decisions, self.p5.scored_vulns, tmp_path
        )
        for r in results:
            assert r.vuln_id != ""
            assert r.strategy != ""
            assert r.cwe != ""
            assert isinstance(r.success, bool)


# ─── Verifier Tests ───────────────────────────────────────────────────────────

class TestPatchVerifier:

    def test_verify_produces_results(self, tmp_path):
        from patch.patch_engine import PatchEngine
        from patch.verifier import PatchVerifier

        p5 = get_phase5_result()
        engine = PatchEngine()
        _, patched = engine.apply_all(p5.decisions, p5.scored_vulns, tmp_path)

        verifier = PatchVerifier()
        results  = verifier.verify(p5.scored_vulns, patched)
        assert len(results) == len(patched)

    def test_verification_has_before_counts(self, tmp_path):
        from patch.patch_engine import PatchEngine
        from patch.verifier import PatchVerifier

        p5 = get_phase5_result()
        engine = PatchEngine()
        _, patched = engine.apply_all(p5.decisions, p5.scored_vulns, tmp_path)

        verifier = PatchVerifier()
        results  = verifier.verify(p5.scored_vulns, patched)
        for r in results:
            assert r.vulns_before > 0

    def test_fix_rate_between_0_and_1(self, tmp_path):
        from patch.patch_engine import PatchEngine
        from patch.verifier import PatchVerifier

        p5 = get_phase5_result()
        engine = PatchEngine()
        _, patched = engine.apply_all(p5.decisions, p5.scored_vulns, tmp_path)

        verifier = PatchVerifier()
        results  = verifier.verify(p5.scored_vulns, patched)
        for r in results:
            assert 0.0 <= r.fix_rate <= 1.0


# ─── Phase 6 End-to-End ──────────────────────────────────────────────────────

class TestPhase6E2E:

    def test_full_pipeline(self, tmp_path):
        from patch.phase6 import run_phase6
        p5 = get_phase5_result()
        p6 = run_phase6(p5, output_dir=str(tmp_path), verbose=False)
        assert len(p6.patch_results) > 0

    def test_artifacts_saved(self, tmp_path):
        from patch.phase6 import run_phase6
        p5 = get_phase5_result()
        run_phase6(p5, output_dir=str(tmp_path), verbose=False)
        assert (tmp_path / "verification.json").exists()

    def test_verification_json_structure(self, tmp_path):
        from patch.phase6 import run_phase6
        p5 = get_phase5_result()
        run_phase6(p5, output_dir=str(tmp_path), verbose=False)
        data = json.loads((tmp_path / "verification.json").read_text())
        assert "patch_results" in data
        assert "verification" in data
        assert "total_fix_rate" in data

    def test_empty_input_handled(self):
        from patch.phase6 import run_phase6
        from agent.phase5 import Phase5Result
        empty = Phase5Result()
        p6 = run_phase6(empty, verbose=False)
        assert p6.n_patched == 0

    def test_summary_keys(self, tmp_path):
        from patch.phase6 import run_phase6
        p5 = get_phase5_result()
        p6 = run_phase6(p5, output_dir=str(tmp_path), verbose=False)
        s  = p6.summary()
        for key in ("n_patched", "n_failed", "fix_rate", "duration_s"):
            assert key in s