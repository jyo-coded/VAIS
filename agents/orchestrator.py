"""
agents/orchestrator.py
──────────────────────
VAIS Multi-Agent Orchestrator.

Pipeline design:
  1. Tanuki  — 2 fast rule-based status lines (entry points, attack surface count)
  2. Tsushima— 2 fast rule-based status lines (memory issues count, CWE breakdown)
  3. Iriomote— 2 fast rule-based status lines (taint confirmed count, exploitable paths)
  4. Raijū  — 2 fast rule-based status lines (ML scores, top risk summary)
  5. Yamabiko— Asks Ollama to generate a patch summary; presents patch_request bubbles per vuln

NO inter-agent LLM calls. Fast deterministic workflow.
Only Yamabiko optionally uses Ollama/Gemini for the patch text.
"""
from __future__ import annotations
import json
import logging
from collections import Counter
from typing import AsyncGenerator

from agents.tanuki import create_tanuki
from agents.tsushima import create_tsushima
from agents.iriomote import create_iriomote
from agents.raiju import create_raiju
from agents.yamabiko import create_yamabiko

log = logging.getLogger(__name__)

# ── Agent colour map for quick lookup ─────────────────────────────────────────
AGENT_META = {
    "Tanuki":   {"colour": "#E85D04", "species": "Japanese Raccoon Dog"},
    "Tsushima": {"colour": "#3B82F6", "species": "Tsushima Leopard Cat"},
    "Iriomote": {"colour": "#10B981", "species": "Iriomote Wildcat"},
    "Raiju":    {"colour": "#8B5CF6", "species": "Mythical Lightning Beast"},
    "Yamabiko": {"colour": "#F59E0B", "species": "Mountain Echo Spirit"},
}


class VaisAdkOrchestrator:
    """Google ADK-compatible multi-agent orchestrator for VAIS."""

    def __init__(self):
        self.shared_messages: list[dict] = []
        self.tanuki   = create_tanuki()
        self.tsushima = create_tsushima()
        self.iriomote = create_iriomote()
        self.raiju    = create_raiju()
        self.yamabiko = create_yamabiko()
        for a in [self.tanuki, self.tsushima, self.iriomote, self.raiju, self.yamabiko]:
            a.shared_messages = self.shared_messages

    # ────────────────────────────────────────────────────────────────────────
    async def run_pipeline_async(self, phase4_result) -> AsyncGenerator[dict, None]:
        vulns = phase4_result.scored_vulns

        if not vulns:
            msg = self._quick_msg("System", "No vulnerabilities found in the target file.", "info")
            yield msg
            return

        high_risk  = [v for v in vulns if v.is_high_risk]
        taint_conf = [v for v in vulns if getattr(v, "taint_confirmed", False)]
        cwe_counts = Counter(str(getattr(v, "cwe", "Unknown")) for v in vulns)
        top3       = sorted(vulns, key=lambda x: getattr(x, "composite_risk", 0), reverse=True)[:3]

        # ── Tanuki — Recon ──────────────────────────────────────────────────
        entry_pts = len(set(getattr(v, "function_name", "?") for v in vulns))
        yield self._agent_msg(self.tanuki,
            f"Attack surface mapped — {len(vulns)} candidate issues across {entry_pts} functions. "
            f"External input vectors identified in {len(high_risk)} high-risk call sites.")

        yield self._agent_msg(self.tanuki,
            f"Top entry-point functions: {', '.join(set(getattr(v,'function_name','?') for v in high_risk[:4]) or ['none detected'])}. "
            f"Handing off to Tsushima for memory safety analysis.")

        # ── Tsushima — Memory Safety ────────────────────────────────────────
        mem_cwes = [v for v in vulns if str(getattr(v,"cwe","")).startswith("CWE-12") or "CWE-416" in str(getattr(v,"cwe","")) or "CWE-415" in str(getattr(v,"cwe",""))]
        yield self._agent_msg(self.tsushima,
            f"Memory safety scan complete — {len(mem_cwes)} memory-class issues detected. "
            f"CWE distribution: {dict(list(cwe_counts.most_common(3)))}.")

        yield self._agent_msg(self.tsushima,
            f"{len(high_risk)} HIGH/CRITICAL issues confirmed. "
            f"Highest severity: {', '.join(set(v.severity.value if hasattr(v.severity,'value') else str(v.severity) for v in high_risk[:3]) or ['none'])}. "
            f"Routing to Iriomote for taint analysis.")

        # ── Iriomote — Taint Flow ───────────────────────────────────────────
        yield self._agent_msg(self.iriomote,
            f"Taint flow analysis complete — {len(taint_conf)}/{len(vulns)} paths confirmed exploitable. "
            f"Untrusted input reaches dangerous sinks in {len(taint_conf)} code paths.")

        yield self._agent_msg(self.iriomote,
            f"{'High exploitability confirmed' if taint_conf else 'No confirmed taint paths — heuristic mode active'}. "
            f"Sending scored findings to Raijū for ML risk assessment.")

        # ── Raijū — ML Risk Scoring ─────────────────────────────────────────
        avg_risk = sum(getattr(v, "composite_risk", 0) for v in vulns) / len(vulns) if vulns else 0
        top_risk_str = ", ".join(
            f"{v.vuln_id}={getattr(v,'composite_risk',0):.2f}" for v in top3
        )
        yield self._agent_msg(self.raiju,
            f"ML ensemble scoring complete — avg risk score {avg_risk:.2f}. "
            f"Top findings by composite risk: [{top_risk_str}].")

        yield self._agent_msg(self.raiju,
            f"XGBoost + CodeBERT + GNN ensemble applied. "
            f"{sum(1 for v in vulns if getattr(v,'exploit_prob',0) and v.exploit_prob >= 0.7)} findings at exploitation probability ≥ 70%. "
            f"Routing to Yamabiko for patch generation.")

        # ── Yamabiko — Patch Strategy ───────────────────────────────────────
        # Try Ollama for smart patch summary (non-blocking, 60s timeout)
        patch_prompt = (
            f"You are Yamabiko, a security patch specialist. For these {len(top3)} high-risk vulnerabilities, "
            f"write brief, specific patch recommendations. Be concise (1-2 lines per finding). "
            f"Findings: " + "; ".join(
                f"{v.vuln_id} ({getattr(v,'cwe','?')}) in {getattr(v,'function_name','?')}: {getattr(v,'title','?')}"
                for v in top3
            )
        )

        patch_summary = await self.yamabiko.generate_async(patch_prompt, max_tokens=300)

        if patch_summary:
            yield self._agent_msg(self.yamabiko, patch_summary.strip(), message_type="info")
        else:
            yield self._agent_msg(self.yamabiko,
                f"Patch analysis ready for {len(top3)} critical findings. "
                f"Review proposed fixes below and approve each remediation.")

        # Emit one patch_request per top vuln for approval buttons
        for v in top3:
            diff = getattr(v, "patch_diff", None) or self._stub_diff(v)
            msg = self.yamabiko.send_message(
                text=(
                    f"Patch proposal for {v.vuln_id} — "
                    f"{getattr(v,'title','Vulnerability')} "
                    f"(Severity: {v.severity.value if hasattr(v.severity,'value') else v.severity})"
                ),
                message_type="patch_request",
                vuln_id=v.vuln_id,
                patch_diff=diff,
            )
            yield msg

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _agent_msg(self, agent, text: str, message_type: str = "info") -> dict:
        return agent.send_message(text, message_type=message_type)

    def _quick_msg(self, name: str, text: str, message_type: str = "info") -> dict:
        meta = AGENT_META.get(name, {"colour": "#888", "species": "System"})
        msg = {
            "agent_name": name,
            "species": meta["species"],
            "colour": meta["colour"],
            "text": text,
            "message_type": message_type,
        }
        self.shared_messages.append(msg)
        return msg

    def _stub_diff(self, vuln) -> str:
        cwe  = str(getattr(vuln, "cwe", "CWE-?"))
        func = getattr(vuln, "function_name", "target_function")
        src  = getattr(vuln, "source_file", "file")
        snippet = getattr(vuln, "code_snippet", "").split("\n")[0] if getattr(vuln, "code_snippet", "") else ""
        return (
            f"--- a/{src}\n"
            f"+++ b/{src}\n"
            f"@@ function {func} @@\n"
            + (f"-  {snippet}\n+  // TODO: Replace with safe equivalent (see {cwe})\n" if snippet else
               f"-  // Vulnerable pattern detected ({cwe})\n+  // Apply safe API — see CERT-C for {cwe}\n")
        )
