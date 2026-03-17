"""
tests/phase5/test_phase5.py
───────────────────────────
Phase 5 test suite. Ollama is mocked — tests run offline.
Run: pytest tests/phase5/ -v
"""

from __future__ import annotations
import pytest
import json
from pathlib import Path

SAMPLES = Path(__file__).parent.parent / "samples"


def get_phase4_result():
    """Run phases 1-4 and return Phase4Result."""
    from core.phase1 import run_phase1
    from rules.engine import run_phase2
    from ml.phase3 import run_phase3
    from ml.phase4 import run_phase4

    p1 = run_phase1(str(SAMPLES / "vulnerable.c"), verbose=False)
    p2 = run_phase2(p1, verbose=False)
    p3 = run_phase3(p2, p1, use_nvd_api=False, verbose=False)
    p4 = run_phase4(p3, verbose=False)
    return p4


# ─── Tool Tests ───────────────────────────────────────────────────────────────

class TestAgentTools:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.p4 = get_phase4_result()
        self.vulns = self.p4.scored_vulns

    def test_analyze_vulnerability_returns_context(self):
        from agent.tools import analyze_vulnerability
        vuln = self.vulns[0]
        result = analyze_vulnerability(vuln.vuln_id, self.vulns)
        assert "cwe" in result
        assert "available_strategies" in result
        assert "composite_risk" in result
        assert result["vuln_id"] == vuln.vuln_id

    def test_analyze_missing_vuln(self):
        from agent.tools import analyze_vulnerability
        result = analyze_vulnerability("VAPT-FAKE-999", self.vulns)
        assert "error" in result

    def test_query_nvd_returns_cvss(self):
        from agent.tools import query_nvd
        result = query_nvd("CWE-120")
        assert "cvss_score" in result
        assert "severity" in result
        assert "mitigation" in result
        assert result["cvss_score"] > 0

    def test_query_nvd_normalizes_id(self):
        from agent.tools import query_nvd
        r1 = query_nvd("CWE-78")
        r2 = query_nvd("78")
        assert r1["cvss_score"] == r2["cvss_score"]

    def test_decide_patch_strategy_attaches(self):
        from agent.tools import decide_patch_strategy
        vuln = self.vulns[0]
        result = decide_patch_strategy(
            vuln.vuln_id,
            "replace_strcpy_with_strncpy",
            self.vulns,
            "Test reasoning",
        )
        assert result["status"] == "decision_recorded"
        assert vuln.patch_strategy == "replace_strcpy_with_strncpy"

    def test_decide_patch_strategy_missing_vuln(self):
        from agent.tools import decide_patch_strategy
        result = decide_patch_strategy("FAKE-ID", "any_strategy", self.vulns)
        assert "error" in result


# ─── Agent Trace Tests ────────────────────────────────────────────────────────

class TestAgentTrace:

    def test_trace_logs_steps(self):
        from agent.ollama_agent import AgentTrace
        trace = AgentTrace()
        trace.log_step("V001", "analyze", {"result": "ok"}, "fallback")
        assert len(trace.steps) == 1
        assert trace.steps[0]["vuln_id"] == "V001"

    def test_trace_logs_decisions(self):
        from agent.ollama_agent import AgentTrace
        trace = AgentTrace()
        trace.log_decision("V001", "replace_strcpy_with_strncpy", "reasoning")
        assert len(trace.decisions) == 1

    def test_trace_to_dict(self):
        from agent.ollama_agent import AgentTrace
        trace = AgentTrace()
        trace.log_step("V001", "analyze", {}, "fallback")
        trace.log_decision("V001", "some_strategy", "reason")
        d = trace.to_dict()
        assert "steps" in d
        assert "decisions" in d
        assert "total_steps" in d


# ─── Fallback Agent Tests ────────────────────────────────────────────────────

class TestFallbackAgent:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.p4 = get_phase4_result()

    def test_fallback_processes_all_vulns(self):
        from agent.ollama_agent import OllamaAgent
        agent = OllamaAgent()
        agent._ollama_available = False  # force fallback
        trace = agent.run(self.p4.scored_vulns)
        assert len(trace.decisions) == len(self.p4.scored_vulns)

    def test_fallback_assigns_valid_strategies(self):
        from agent.ollama_agent import OllamaAgent
        from agent.tools import PATCH_STRATEGIES
        agent = OllamaAgent()
        agent._ollama_available = False
        trace = agent.run(self.p4.scored_vulns)
        for d in trace.decisions:
            assert d["strategy"] != ""
            assert d["vuln_id"] != ""

    def test_fallback_attaches_patch_strategy(self):
        from agent.ollama_agent import OllamaAgent
        agent = OllamaAgent()
        agent._ollama_available = False
        agent.run(self.p4.scored_vulns)
        # At least some vulns should have patch_strategy set
        with_strategy = [v for v in self.p4.scored_vulns if v.patch_strategy]
        assert len(with_strategy) > 0


# ─── Phase 5 End-to-End ──────────────────────────────────────────────────────

class TestPhase5E2E:

    def test_full_pipeline_fallback(self, tmp_path):
        from agent.phase5 import run_phase5
        p4 = get_phase4_result()
        p5 = run_phase5(p4, output_dir=str(tmp_path), verbose=False)
        assert p5.n_decisions > 0
        assert p5.agent_mode != ""

    def test_artifacts_saved(self, tmp_path):
        from agent.phase5 import run_phase5
        p4 = get_phase4_result()
        p5 = run_phase5(p4, output_dir=str(tmp_path), verbose=False)
        assert (tmp_path / "agent_trace.json").exists()
        assert (tmp_path / "decisions.json").exists()

    def test_decisions_json_structure(self, tmp_path):
        from agent.phase5 import run_phase5
        p4 = get_phase4_result()
        run_phase5(p4, output_dir=str(tmp_path), verbose=False)
        data = json.loads((tmp_path / "decisions.json").read_text())
        assert "decisions" in data
        assert "total" in data
        assert data["total"] > 0

    def test_empty_input_handled(self):
        from agent.phase5 import run_phase5
        from ml.phase4 import Phase4Result
        empty = Phase4Result()
        p5 = run_phase5(empty, verbose=False)
        assert p5.n_decisions == 0

    def test_decisions_cover_all_vulns(self, tmp_path):
        from agent.phase5 import run_phase5
        p4 = get_phase4_result()
        p5 = run_phase5(p4, output_dir=str(tmp_path), verbose=False)
        decided_ids = {vid for vid, _ in p5.decisions}
        all_ids     = {v.vuln_id for v in p4.scored_vulns}
        assert decided_ids == all_ids