"""
agent/tools.py
──────────────
Phase 5: Agent Tool Definitions.

Four tools the LLM agent can invoke during its reasoning loop:

  1. analyze_vulnerability   — deep structural analysis of a specific vuln
  2. query_nvd               — fetch real CVE data for a CWE ID
  3. decide_patch_strategy   — select a patch approach for a vuln
  4. rerun_analysis          — re-trigger Phase 1+2 on a patched file

Each tool is a plain Python function.
The agent calls them by name via Ollama tool-calling.
Results are returned as structured dicts the agent can reason over.
"""

from __future__ import annotations
import json
from typing import Any

from rules.vuln_object import VulnObject, Severity
from ml.nvd_client import NVDClient, CWE_CVSS_DEFAULTS

# ─── Patch strategy catalog ──────────────────────────────────────────────────

PATCH_STRATEGIES = {
    "CWE-120": [
        "replace_strcpy_with_strncpy",
        "replace_gets_with_fgets",
        "replace_sprintf_with_snprintf",
        "add_bounds_check",
    ],
    "CWE-121": ["add_stack_bounds_check", "replace_with_safe_alternative"],
    "CWE-122": ["add_heap_bounds_check", "validate_size_before_alloc"],
    "CWE-125": ["add_sizeof_bounds_check", "validate_copy_length"],
    "CWE-134": ["add_literal_format_string", "sanitize_format_argument"],
    "CWE-78":  ["use_execve_arg_array", "sanitize_shell_input", "remove_shell_call"],
    "CWE-416": ["set_pointer_null_after_free", "use_ownership_pattern"],
    "CWE-415": ["add_null_check_before_free", "set_pointer_null_after_free"],
    "CWE-476": ["add_null_pointer_check"],
    "CWE-95":  ["replace_eval_with_literal_eval", "use_ast_parse"],
    "CWE-502": ["replace_pickle_with_json", "validate_before_deserialize"],
    "CWE-22":  ["validate_path_with_abspath", "use_safe_path_join"],
    "CWE-798": ["move_to_env_variable", "use_secrets_manager"],
    "CWE-78":  ["use_arg_list_no_shell", "sanitize_input"],
    "CWE-242": ["remove_unsafe_pointer", "use_safe_alternative"],
    "CWE-390": ["add_error_handling", "propagate_error_return"],
    "CWE-20":  ["add_input_validation", "add_bounds_check"],
    "CWE-362": ["add_mutex_lock", "use_atomic_operation"],
}

# ─── Tool 1: Analyze Vulnerability ───────────────────────────────────────────

def analyze_vulnerability(
    vuln_id:     str,
    scored_vulns: list[VulnObject],
) -> dict[str, Any]:
    """
    Deep structural analysis of a specific vulnerability.
    Returns rich context the agent uses to reason about patch strategy.
    """
    vuln = _find_vuln(vuln_id, scored_vulns)
    if not vuln:
        return {"error": f"Vulnerability {vuln_id} not found"}

    strategies = PATCH_STRATEGIES.get(vuln.cwe.value, ["manual_review"])

    return {
        "vuln_id":            vuln.vuln_id,
        "cwe":                vuln.cwe.value,
        "rule":               vuln.rule_name,
        "title":              vuln.title,
        "location":           vuln.location_str,
        "function":           vuln.function_name,
        "severity":           vuln.severity.value,
        "ml_severity":        vuln.ml_severity.value if vuln.ml_severity else None,
        "exploit_prob":       vuln.exploit_prob,
        "risk_score":         vuln.risk_score,
        "composite_risk":     round(vuln.composite_risk, 4),
        "reachable":          vuln.reachable_from_entry,
        "extern_input":       vuln.has_extern_input,
        "call_depth":         vuln.call_depth,
        "in_loop":            vuln.in_loop,
        "code_snippet":       vuln.code_snippet,
        "description":        vuln.description,
        "available_strategies": strategies,
        "recommended_strategy": strategies[0] if strategies else "manual_review",
    }


# ─── Tool 2: Query NVD ───────────────────────────────────────────────────────

def query_nvd(cwe_id: str) -> dict[str, Any]:
    """
    Get real CVE statistics for a CWE ID from NVD.
    Returns CVSS score, severity label, and mitigation guidance.
    """
    # Normalize
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"

    # Use offline defaults (fast, no network needed)
    client = NVDClient(use_api=False)
    cvss = client.get_cvss_score(cwe_id)

    severity = (
        "CRITICAL" if cvss >= 9.0 else
        "HIGH"     if cvss >= 7.0 else
        "MEDIUM"   if cvss >= 4.0 else
        "LOW"
    )

    # Mitigation guidance per CWE
    mitigations = {
        "CWE-120": "Use bounded string functions: strncpy, strlcpy, snprintf. Always check buffer size.",
        "CWE-78":  "Never pass user input to shell. Use execve() with argument arrays instead of system().",
        "CWE-134": "Always use a string literal as the format argument. Never pass user input as format string.",
        "CWE-416": "Set pointers to NULL immediately after free(). Use ownership patterns to track lifetimes.",
        "CWE-415": "Add NULL check before free(). Set pointer to NULL after first free().",
        "CWE-95":  "Replace eval()/exec() with ast.literal_eval() for safe value parsing.",
        "CWE-502": "Never deserialize untrusted pickle data. Use json or protobuf instead.",
        "CWE-22":  "Validate paths with os.path.abspath() and confirm they start with allowed base directory.",
        "CWE-798": "Store secrets in environment variables or a secrets manager. Never commit to source.",
        "CWE-242": "Avoid unsafe package. Audit all uintptr conversions. Document necessity clearly.",
        "CWE-390": "Always check error return values. Use named returns or wrapper functions.",
        "CWE-20":  "Validate all input before use. Check bounds, types, and ranges explicitly.",
    }

    return {
        "cwe_id":     cwe_id,
        "cvss_score": cvss,
        "severity":   severity,
        "mitigation": mitigations.get(cwe_id, "Review OWASP and CERT guidelines for this CWE."),
        "reference":  f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
    }


# ─── Tool 3: Decide Patch Strategy ───────────────────────────────────────────

def decide_patch_strategy(
    vuln_id:        str,
    strategy:       str,
    scored_vulns:   list[VulnObject],
    reasoning:      str = "",
) -> dict[str, Any]:
    """
    Record the agent's patch strategy decision for a vulnerability.
    Validates the strategy and attaches it to the VulnObject.
    Returns confirmation with the decision recorded.
    """
    vuln = _find_vuln(vuln_id, scored_vulns)
    if not vuln:
        return {"error": f"Vulnerability {vuln_id} not found"}

    # Validate strategy exists for this CWE
    valid_strategies = PATCH_STRATEGIES.get(vuln.cwe.value, [])
    if strategy not in valid_strategies and strategy != "manual_review":
        # Accept anyway — agent may suggest novel strategies
        vuln.add_agent_note(f"Non-standard strategy selected: {strategy}")

    # Attach decision to VulnObject
    vuln.patch_strategy = strategy
    if reasoning:
        vuln.add_agent_note(f"Agent reasoning: {reasoning}")

    return {
        "vuln_id":        vuln_id,
        "strategy":       strategy,
        "cwe":            vuln.cwe.value,
        "status":         "decision_recorded",
        "reasoning":      reasoning,
        "next_step":      "patch_engine will apply this strategy in Phase 6",
    }


# ─── Tool 4: Rerun Analysis ───────────────────────────────────────────────────

def rerun_analysis(
    file_path:  str,
    context:    str = "",
) -> dict[str, Any]:
    """
    Re-trigger Phase 1 + Phase 2 on a (patched) file.
    Used by agent to verify a patch actually fixed the vulnerability.
    This is the ONLY backwards call allowed in the pipeline.
    """
    from pathlib import Path
    from core.phase1 import run_phase1
    from rules.engine import run_phase2

    if not Path(file_path).exists():
        return {
            "error": f"File not found: {file_path}",
            "status": "failed",
        }

    try:
        p1 = run_phase1(file_path, verbose=False)
        p2 = run_phase2(p1, verbose=False)

        summary = p2.collection.summary()
        return {
            "file":           file_path,
            "status":         "complete",
            "total_vulns":    summary["total"],
            "critical":       summary["critical"],
            "high":           summary["high"],
            "medium":         summary["medium"],
            "low":            summary["low"],
            "context":        context,
            "note": (
                "Vulnerabilities remain — patch may be incomplete."
                if summary["total"] > 0
                else "No vulnerabilities detected — patch appears successful."
            ),
        }
    except Exception as e:
        return {
            "file":   file_path,
            "status": "error",
            "error":  str(e),
        }


# ─── Helper ───────────────────────────────────────────────────────────────────

def _find_vuln(vuln_id: str, vulns: list[VulnObject]) -> VulnObject | None:
    for v in vulns:
        if v.vuln_id == vuln_id:
            return v
    return None


# ─── Tool schema for Ollama ───────────────────────────────────────────────────

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "analyze_vulnerability",
            "description": "Get deep structural analysis of a specific vulnerability including code context, risk scores, and available patch strategies.",
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_id": {
                        "type": "string",
                        "description": "The vulnerability ID to analyze (e.g. VAPT-C-001)"
                    }
                },
                "required": ["vuln_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "query_nvd",
            "description": "Get CVSS score, severity rating, and mitigation guidance for a CWE ID from the National Vulnerability Database.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cwe_id": {
                        "type": "string",
                        "description": "The CWE ID to query (e.g. CWE-78 or CWE-120)"
                    }
                },
                "required": ["cwe_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "decide_patch_strategy",
            "description": "Record your patch strategy decision for a vulnerability. Call this when you have decided how to fix a specific vulnerability.",
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_id": {
                        "type": "string",
                        "description": "The vulnerability ID to patch"
                    },
                    "strategy": {
                        "type": "string",
                        "description": "The patch strategy to apply (e.g. replace_strcpy_with_strncpy)"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Brief explanation of why this strategy was chosen"
                    }
                },
                "required": ["vuln_id", "strategy"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "rerun_analysis",
            "description": "Re-run Phase 1+2 vulnerability analysis on a file. Use this to verify a patch actually fixed the vulnerability.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to re-analyze"
                    },
                    "context": {
                        "type": "string",
                        "description": "Brief context about why re-analysis was triggered"
                    }
                },
                "required": ["file_path"]
            }
        }
    },
]