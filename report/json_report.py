"""
report/json_report.py
─────────────────────
Phase 7: JSON Report Generator.

Produces a machine-readable full JSON report combining all phase outputs.
Suitable for CI/CD integration, dashboards, and further tooling.
"""

from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Optional


def generate_json_report(
    all_results: dict,
    output_path: Optional[str] = None,
) -> dict:
    """
    Generate a full JSON report from all phase results.

    Returns the report dict. Saves to output_path if provided.
    """
    p1 = all_results.get("phase1")
    p2 = all_results.get("phase2")
    p3 = all_results.get("phase3")
    p4 = all_results.get("phase4")
    p5 = all_results.get("phase5")
    p6 = all_results.get("phase6")

    vulns = p4.sorted_by_risk() if p4 else []

    # ── Build report ──────────────────────────────────────────────────────
    report = {
        "meta": {
            "tool":       "VAPT Intelligence System",
            "version":    "1.0.0",
            "generated":  datetime.now().isoformat(),
            "languages":  ["C", "Python", "Go"],
        },
        "summary": _build_summary(vulns, p5, p6),
        "phase_metrics": _build_phase_metrics(p1, p2, p3, p4, p5, p6),
        "vulnerabilities": [_vuln_to_dict(v) for v in vulns],
        "patch_results": [
            pr.to_dict() for pr in (p6.patch_results if p6 else [])
        ],
        "verification": [
            vr.to_dict() for vr in (p6.verification if p6 else [])
        ],
        "agent_decisions": [
            {"vuln_id": vid, "strategy": strat}
            for vid, strat in (p5.decisions if p5 else [])
        ],
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    return report


def _build_summary(vulns, p5, p6) -> dict:
    from rules.vuln_object import Severity
    n = len(vulns)
    return {
        "total_vulnerabilities": n,
        "by_severity": {
            "CRITICAL": sum(1 for v in vulns if v.severity == Severity.CRITICAL),
            "HIGH":     sum(1 for v in vulns if v.severity == Severity.HIGH),
            "MEDIUM":   sum(1 for v in vulns if v.severity == Severity.MEDIUM),
            "LOW":      sum(1 for v in vulns if v.severity == Severity.LOW),
            "INFO":     sum(1 for v in vulns if v.severity == Severity.INFO),
        },
        "by_cwe": _count_by(vulns, lambda v: v.cwe.value),
        "by_language": _count_by(vulns, lambda v: str(v.language)),
        "avg_risk_score":    round(
            sum(v.risk_score or 0 for v in vulns) / max(n, 1), 4
        ),
        "avg_exploit_prob":  round(
            sum(v.exploit_prob or 0 for v in vulns) / max(n, 1), 4
        ),
        "high_risk_count":   sum(1 for v in vulns if (v.risk_score or 0) >= 0.7),
        "patch_decisions":   p5.n_decisions if p5 else 0,
        "patches_applied":   p6.n_patched   if p6 else 0,
        "fix_rate":          p6.total_fix_rate if p6 else 0.0,
    }


def _build_phase_metrics(p1, p2, p3, p4, p5, p6) -> dict:
    return {
        "phase1": {
            "files_parsed":      p1.summary().get("files_parsed", 0) if p1 else 0,
            "functions_found":   p1.summary().get("total_functions", 0) if p1 else 0,
            "duration_s":        p1.summary().get("duration_s", 0) if p1 else 0,
        } if p1 else {},
        "phase2": {
            "files_scanned":     p2.summary().get("files_scanned", 0) if p2 else 0,
            "total_findings":    p2.summary().get("total_findings", 0) if p2 else 0,
            "rules_fired":       p2.summary().get("rules_fired", 0) if p2 else 0,
            "duration_s":        p2.summary().get("duration_s", 0) if p2 else 0,
        } if p2 else {},
        "phase3": {
            "n_vulns":           p3.n_vulns if p3 else 0,
            "n_features":        p3.X.shape[1] if p3 and p3.X is not None else 0,
            "nvd_online":        p3.nvd_online if p3 else False,
            "duration_s":        p3.duration_s if p3 else 0,
        } if p3 else {},
        "phase4": {
            "n_scored":          p4.n_vulns if p4 else 0,
            "classifier_acc":    p4.metrics.get("classifier", {}).get("accuracy", 0) if p4 else 0,
            "classifier_auc":    p4.metrics.get("classifier", {}).get("auc_roc", 0) if p4 else 0,
            "regressor_mae":     p4.metrics.get("regressor", {}).get("mae", 0) if p4 else 0,
            "regressor_r2":      p4.metrics.get("regressor", {}).get("r2_score", 0) if p4 else 0,
            "duration_s":        p4.duration_s if p4 else 0,
        } if p4 else {},
        "phase5": {
            "n_decisions":       p5.n_decisions if p5 else 0,
            "agent_mode":        p5.agent_mode if p5 else "",
            "errors":            len(p5.errors) if p5 else 0,
            "duration_s":        p5.duration_s if p5 else 0,
        } if p5 else {},
        "phase6": {
            "n_patched":         p6.n_patched if p6 else 0,
            "n_failed":          p6.n_failed if p6 else 0,
            "fix_rate":          p6.total_fix_rate if p6 else 0.0,
            "duration_s":        p6.duration_s if p6 else 0,
        } if p6 else {},
    }


def _vuln_to_dict(v) -> dict:
    return {
        "vuln_id":        v.vuln_id,
        "cwe":            v.cwe.value,
        "rule":           v.rule_name,
        "title":          v.title,
        "severity":       v.severity.value,
        "ml_severity":    v.ml_severity.value if v.ml_severity else None,
        "function":       v.function_name,
        "file":           str(v.source_file),
        "line":           v.line_start,
        "exploit_prob":   v.exploit_prob,
        "risk_score":     v.risk_score,
        "composite_risk": round(v.composite_risk, 4),
        "reachable":      v.reachable_from_entry,
        "extern_input":   v.has_extern_input,
        "patch_strategy": v.patch_strategy,
        "description":    v.description,
        "snippet":        v.code_snippet,
    }


def _count_by(vulns, key_fn) -> dict:
    from collections import Counter
    return dict(Counter(key_fn(v) for v in vulns))