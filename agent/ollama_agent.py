"""
agent/ollama_agent.py
─────────────────────
Phase 5: Ollama LLM Agent.

Uses prompt-based tool dispatch (works with CodeLlama, Mistral, Llama3).
Native Ollama tool-calling is unreliable with CodeLlama — instead we:
  1. Send a structured prompt describing the vuln + available strategies
  2. Ask the model to respond with a JSON decision
  3. Parse the JSON and record the patch strategy

Falls back to rule-based selection if Ollama is unavailable or
if the model output cannot be parsed after retries.
"""

from __future__ import annotations
import json
import re
import time
from typing import Any, Optional

from rules.vuln_object import VulnObject
from agent.tools import (
    analyze_vulnerability,
    query_nvd,
    decide_patch_strategy,
    PATCH_STRATEGIES,
)

# ─── Config ───────────────────────────────────────────────────────────────────

DEFAULT_MODEL     = "qwen2.5-coder:1.5b"
FALLBACK_MODEL    = "codellama"
MAX_VULNS_PER_RUN = 20
OLLAMA_TIMEOUT    = 60


class AgentTrace:
    """Records the full reasoning trace for audit and report generation."""

    def __init__(self):
        self.steps:     list[dict] = []
        self.decisions: list[dict] = []
        self.errors:    list[str]  = []
        self.start_time = time.time()

    def log_step(self, vuln_id: str, action: str, result: Any, model: str = "") -> None:
        self.steps.append({
            "timestamp": round(time.time() - self.start_time, 3),
            "vuln_id":   vuln_id,
            "action":    action,
            "result":    result,
            "model":     model,
        })

    def log_decision(self, vuln_id: str, strategy: str, reasoning: str) -> None:
        self.decisions.append({
            "vuln_id":   vuln_id,
            "strategy":  strategy,
            "reasoning": reasoning,
        })

    def log_error(self, error: str) -> None:
        self.errors.append(error)

    def to_dict(self) -> dict:
        return {
            "total_steps":     len(self.steps),
            "total_decisions": len(self.decisions),
            "errors":          self.errors,
            "duration_s":      round(time.time() - self.start_time, 3),
            "steps":           self.steps,
            "decisions":       self.decisions,
        }


class OllamaAgent:
    """
    LLM-powered vulnerability triage and patch strategy agent.

    Sends each vulnerability as a structured prompt to CodeLlama/Mistral,
    asks for a JSON decision, parses it, and records the patch strategy.

    Gracefully degrades to rule-based fallback if Ollama is unavailable
    or if the model output cannot be parsed.
    """

    def __init__(self, model: str = DEFAULT_MODEL):
        self.model             = model
        self._client           = None
        self._ollama_available = False
        self._active_model     = None

    def initialize(self) -> bool:
        """Try to connect to Ollama. Returns True if a usable model is found."""
        try:
            import ollama
            resp      = ollama.list()
            
            if hasattr(resp, 'models'):
                available = [m.model for m in resp.models]
            else:
                available = [m.get("name", m.get("model")) for m in resp.get("models", [])]

            for candidate in [self.model, FALLBACK_MODEL]:
                if any(candidate in m for m in available):
                    self._client           = ollama
                    self._active_model     = candidate
                    self._ollama_available = True
                    return True

            return False
        except Exception:
            return False

    def run(
        self,
        scored_vulns: list[VulnObject],
        max_vulns:    int = MAX_VULNS_PER_RUN,
    ) -> AgentTrace:
        """Main agent loop — process each vulnerability in risk-priority order."""
        trace = AgentTrace()

        priority_vulns = sorted(
            scored_vulns,
            key=lambda v: v.composite_risk,
            reverse=True,
        )[:max_vulns]

        if self._ollama_available:
            self._run_llm_loop(priority_vulns, scored_vulns, trace)
        else:
            self._run_fallback_loop(priority_vulns, scored_vulns, trace)

        return trace

    # ── LLM loop ──────────────────────────────────────────────────────────────

    def _run_llm_loop(
        self,
        priority_vulns: list[VulnObject],
        all_vulns:      list[VulnObject],
        trace:          AgentTrace,
    ) -> None:
        """Prompt-based LLM loop — one structured call per vulnerability."""
        for vuln in priority_vulns:
            try:
                self._process_vuln_with_llm(vuln, all_vulns, trace)
            except Exception as e:
                trace.log_error(f"{vuln.vuln_id}: LLM error — {e}")
                self._apply_fallback_decision(vuln, all_vulns, trace)

    def _process_vuln_with_llm(
        self,
        vuln:      VulnObject,
        all_vulns: list[VulnObject],
        trace:     AgentTrace,
    ) -> None:
        """Send one vuln to the LLM, parse its JSON decision."""
        analysis   = analyze_vulnerability(vuln.vuln_id, all_vulns)
        nvd_info   = query_nvd(vuln.cwe.value)
        strategies = analysis.get("available_strategies", ["manual_review"])

        trace.log_step(vuln.vuln_id, "analyze",   analysis, self._active_model)
        trace.log_step(vuln.vuln_id, "query_nvd", nvd_info, self._active_model)

        prompt = self._build_decision_prompt(vuln, analysis, nvd_info, strategies)

        try:
            response = self._client.chat(
                model=self._active_model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.1, "num_predict": 200},
            )
            if hasattr(response, 'message'):
                raw = response.message.content
            else:
                raw = response.get("message", {}).get("content", "")
        except Exception as e:
            raise RuntimeError(f"Ollama call failed: {e}")

        trace.log_step(vuln.vuln_id, "llm_response", raw[:500], self._active_model)

        strategy, reasoning = self._parse_decision(raw, strategies)
        decide_patch_strategy(vuln.vuln_id, strategy, all_vulns, reasoning)
        trace.log_decision(vuln.vuln_id, strategy, reasoning)

    def _build_decision_prompt(
        self,
        vuln:       VulnObject,
        analysis:   dict,
        nvd_info:   dict,
        strategies: list[str],
    ) -> str:
        snippet = (vuln.code_snippet or "").strip()[:300]
        strats  = "\n".join(f"  - {s}" for s in strategies)

        return f"""You are a security engineer. Choose a patch strategy for this vulnerability.

VULNERABILITY:
  ID:           {vuln.vuln_id}
  CWE:          {vuln.cwe.value}
  Severity:     {vuln.severity.value}
  Function:     {vuln.function_name} (line {vuln.line_start})
  Exploit prob: {vuln.exploit_prob}
  Reachable:    {vuln.reachable_from_entry}
  Extern input: {vuln.has_extern_input}
  Code:         {snippet}

NVD INFO:
  CVSS Score:   {nvd_info.get('cvss_score', 'N/A')}
  Mitigation:   {nvd_info.get('mitigation', 'N/A')}

AVAILABLE STRATEGIES (pick exactly one from this list):
{strats}

Respond with ONLY this JSON, no other text:
{{"strategy": "<chosen_strategy>", "reasoning": "<one sentence why>"}}"""

    def _parse_decision(
        self,
        raw:        str,
        strategies: list[str],
    ) -> tuple[str, str]:
        """Parse JSON from LLM response. Multi-stage fallback."""
        # Stage 1: clean JSON block
        match = re.search(r'\{[^{}]+\}', raw, re.DOTALL)
        if match:
            try:
                data      = json.loads(match.group())
                strategy  = str(data.get("strategy", "")).strip()
                reasoning = str(data.get("reasoning", "LLM decision")).strip()

                if strategy in strategies:
                    return strategy, reasoning

                # Fuzzy match
                for s in strategies:
                    if s in strategy or strategy in s:
                        return s, reasoning

                if strategy:
                    return strategy, f"[LLM proposed] {reasoning}"

            except (json.JSONDecodeError, Exception):
                pass

        # Stage 2: scan raw text for any known strategy name
        for s in strategies:
            if s in raw:
                return s, "Strategy name found in LLM response"

        # Stage 3: default
        default = strategies[0] if strategies else "manual_review"
        return default, "Default strategy (could not parse LLM response)"

    # ── Rule-based fallback ───────────────────────────────────────────────────

    def _run_fallback_loop(
        self,
        priority_vulns: list[VulnObject],
        all_vulns:      list[VulnObject],
        trace:          AgentTrace,
    ) -> None:
        """Deterministic rule-based fallback — no LLM needed."""
        trace.log_step("system", "mode", "fallback_rule_based", "none")
        for vuln in priority_vulns:
            self._apply_fallback_decision(vuln, all_vulns, trace)

    def _apply_fallback_decision(
        self,
        vuln:      VulnObject,
        all_vulns: list[VulnObject],
        trace:     AgentTrace,
    ) -> None:
        """Pick the primary strategy for this CWE deterministically."""
        analysis   = analyze_vulnerability(vuln.vuln_id, all_vulns)
        nvd_info   = query_nvd(vuln.cwe.value)
        strategies = PATCH_STRATEGIES.get(vuln.cwe.value, ["manual_review"])
        chosen     = strategies[0]

        reasoning = (
            f"Rule-based: {vuln.cwe.value} (CVSS={nvd_info['cvss_score']}) "
            f"in '{vuln.function_name}' line {vuln.line_start}. "
            f"Primary strategy for {vuln.cwe.value}."
        )

        decide_patch_strategy(vuln.vuln_id, chosen, all_vulns, reasoning)
        trace.log_step(vuln.vuln_id, "analyze",   analysis,             "fallback")
        trace.log_step(vuln.vuln_id, "query_nvd", nvd_info,             "fallback")
        trace.log_step(vuln.vuln_id, "decide",    {"strategy": chosen}, "fallback")
        trace.log_decision(vuln.vuln_id, chosen, reasoning)

    @property
    def mode(self) -> str:
        if self._ollama_available:
            return f"llm:{self._active_model}"
        return "fallback:rule_based"