"""
tests/phase7/test_phase7.py
───────────────────────────
Phase 7 test suite.
Run: pytest tests/phase7/ -v
"""

from __future__ import annotations
import json
import pytest
from pathlib import Path

SAMPLES = Path(__file__).parent.parent / "samples"


def get_all_results():
    """Run phases 1–6 with fallback agent and return all results."""
    from core.phase1 import run_phase1
    from rules.engine import run_phase2
    from ml.phase3 import run_phase3
    from ml.phase4 import run_phase4
    from agent.phase5 import run_phase5
    from patch.phase6 import run_phase6

    p1 = run_phase1(str(SAMPLES / "vulnerable.c"), verbose=False)
    p2 = run_phase2(p1, verbose=False)
    p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
    p4 = run_phase4(p3, verbose=False)
    p5 = run_phase5(p4, verbose=False)
    p6 = run_phase6(p5, verbose=False)

    return {
        "phase1": p1, "phase2": p2, "phase3": p3,
        "phase4": p4, "phase5": p5, "phase6": p6,
    }


# ─── JSON Report Tests ────────────────────────────────────────────────────────

class TestJSONReport:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.results = get_all_results()

    def test_generates_without_error(self, tmp_path):
        from report.json_report import generate_json_report
        r = generate_json_report(self.results, str(tmp_path / "r.json"))
        assert isinstance(r, dict)

    def test_has_required_top_keys(self, tmp_path):
        from report.json_report import generate_json_report
        r = generate_json_report(self.results)
        for key in ("meta", "summary", "vulnerabilities", "patch_results", "verification"):
            assert key in r

    def test_summary_has_severity_counts(self, tmp_path):
        from report.json_report import generate_json_report
        r = generate_json_report(self.results)
        s = r["summary"]
        assert "by_severity" in s
        assert s["total_vulnerabilities"] > 0

    def test_vulnerabilities_have_required_fields(self):
        from report.json_report import generate_json_report
        r = generate_json_report(self.results)
        for v in r["vulnerabilities"]:
            for f in ("vuln_id", "cwe", "severity", "function", "line", "risk_score"):
                assert f in v

    def test_file_saved(self, tmp_path):
        from report.json_report import generate_json_report
        path = tmp_path / "report.json"
        generate_json_report(self.results, str(path))
        assert path.exists()
        data = json.loads(path.read_text())
        assert "summary" in data

    def test_phase_metrics_present(self):
        from report.json_report import generate_json_report
        r = generate_json_report(self.results)
        pm = r["phase_metrics"]
        for phase in ("phase1", "phase2", "phase3", "phase4", "phase5", "phase6"):
            assert phase in pm

    def test_agent_decisions_present(self):
        from report.json_report import generate_json_report
        r = generate_json_report(self.results)
        assert "agent_decisions" in r
        assert len(r["agent_decisions"]) > 0


# ─── HTML Report Tests ────────────────────────────────────────────────────────

class TestHTMLReport:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.results = get_all_results()

    def test_generates_valid_html(self):
        from report.html_report import generate_html_report
        h = generate_html_report(self.results)
        assert h.startswith("<!DOCTYPE html>")
        assert "</html>" in h

    def test_contains_chart_js(self):
        from report.html_report import generate_html_report
        h = generate_html_report(self.results)
        assert "chart.js" in h.lower()

    def test_contains_vuln_ids(self):
        from report.html_report import generate_html_report
        h = generate_html_report(self.results)
        assert "VAPT-C-" in h

    def test_file_saved(self, tmp_path):
        from report.html_report import generate_html_report
        path = tmp_path / "report.html"
        generate_html_report(self.results, str(path))
        assert path.exists()
        assert path.stat().st_size > 5000

    def test_contains_severity_badges(self):
        from report.html_report import generate_html_report
        h = generate_html_report(self.results)
        assert "badge-critical" in h or "badge-high" in h

    def test_contains_patch_section(self):
        from report.html_report import generate_html_report
        h = generate_html_report(self.results)
        assert "Patch Results" in h


# ─── CLI Report Tests ─────────────────────────────────────────────────────────

class TestCLIReport:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.results = get_all_results()

    def test_generates_without_error(self):
        from report.cli_report import generate_cli_report
        text = generate_cli_report(self.results)
        assert isinstance(text, str)
        assert len(text) > 100

    def test_contains_key_sections(self):
        from report.cli_report import generate_cli_report
        text = generate_cli_report(self.results)
        assert "EXECUTIVE SUMMARY" in text
        assert "TOP FINDINGS" in text

    def test_file_saved(self, tmp_path):
        from report.cli_report import generate_cli_report
        path = tmp_path / "cli.txt"
        generate_cli_report(self.results, str(path))
        assert path.exists()


# ─── Phase 7 End-to-End ──────────────────────────────────────────────────────

class TestPhase7E2E:

    def test_full_pipeline(self, tmp_path):
        from report.phase7 import run_phase7
        r = get_all_results()
        p7 = run_phase7(**r, output_dir=str(tmp_path), verbose=False)
        assert "json" in p7.report_paths
        assert "html" in p7.report_paths

    def test_all_files_exist(self, tmp_path):
        from report.phase7 import run_phase7
        r = get_all_results()
        p7 = run_phase7(**r, output_dir=str(tmp_path), verbose=False)
        for path in p7.report_paths.values():
            assert Path(path).exists()

    def test_no_errors(self, tmp_path):
        from report.phase7 import run_phase7
        r = get_all_results()
        p7 = run_phase7(**r, output_dir=str(tmp_path), verbose=False)
        assert len(p7.errors) == 0

    def test_selective_formats(self, tmp_path):
        from report.phase7 import run_phase7
        r = get_all_results()
        p7 = run_phase7(**r, output_dir=str(tmp_path), formats=["json"], verbose=False)
        assert "json" in p7.report_paths
        assert "html" not in p7.report_paths

    def test_benchmark_csv(self, tmp_path):
        from report.phase7 import run_phase7
        r = get_all_results()
        p7 = run_phase7(**r, output_dir=str(tmp_path), formats=["benchmark"], verbose=False)
        assert "benchmark" in p7.report_paths
        content = Path(p7.report_paths["benchmark"]).read_text()
        assert "VAPT System" in content
        assert "Cppcheck" in content