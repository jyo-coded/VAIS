"""
patch/verifier.py
─────────────────
Phase 6: Patch Verifier.

Re-runs Phase 1 + Phase 2 on patched files and computes:
  - before/after vulnerability counts
  - which vulns were fixed (no longer detected)
  - which vulns remain (still detected)
  - fix rate percentage
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from rules.vuln_object import VulnObject


@dataclass
class VerificationResult:
    """Before/after comparison for a patched file."""
    original_file:  str
    patched_file:   str

    vulns_before:   int = 0
    vulns_after:    int = 0
    critical_before: int = 0
    critical_after:  int = 0
    high_before:    int = 0
    high_after:     int = 0

    fixed_vuln_ids:     list[str] = field(default_factory=list)
    remaining_vuln_ids: list[str] = field(default_factory=list)
    error:              str       = ""

    @property
    def vulns_fixed(self) -> int:
        return max(0, self.vulns_before - self.vulns_after)

    @property
    def fix_rate(self) -> float:
        if self.vulns_before == 0:
            return 1.0
        return round(self.vulns_fixed / self.vulns_before, 4)

    def to_dict(self) -> dict:
        return {
            "original_file":   self.original_file,
            "patched_file":    self.patched_file,
            "vulns_before":    self.vulns_before,
            "vulns_after":     self.vulns_after,
            "vulns_fixed":     self.vulns_fixed,
            "fix_rate":        self.fix_rate,
            "critical_before": self.critical_before,
            "critical_after":  self.critical_after,
            "high_before":     self.high_before,
            "high_after":      self.high_after,
            "fixed_vuln_ids":  self.fixed_vuln_ids,
            "remaining_ids":   self.remaining_vuln_ids,
            "error":           self.error,
        }


class PatchVerifier:
    """
    Verifies patches by re-running Phase 1+2 on patched files.
    Computes delta between original and patched vulnerability counts.
    """

    def verify(
        self,
        original_vulns: list[VulnObject],
        patched_files:  dict[str, str],
    ) -> list[VerificationResult]:
        """
        Verify all patched files.

        Args:
            original_vulns:  List of VulnObjects from Phase 2 (before patching)
            patched_files:   Dict of {original_path: patched_path}

        Returns:
            List of VerificationResult per file
        """
        results = []
        for orig_path, patched_path in patched_files.items():
            result = self._verify_file(orig_path, patched_path, original_vulns)
            results.append(result)
        return results

    def _verify_file(
        self,
        orig_path:      str,
        patched_path:   str,
        original_vulns: list[VulnObject],
    ) -> VerificationResult:
        """Re-analyse the patched file and diff the findings."""
        from pathlib import Path

        result = VerificationResult(
            original_file=orig_path,
            patched_file=patched_path,
        )

        # Count original vulns for this file
        orig_file_vulns = [
            v for v in original_vulns
            if str(v.source_file) == str(orig_path)
               or Path(v.source_file).name == Path(orig_path).name
        ]
        result.vulns_before    = len(orig_file_vulns)
        result.critical_before = sum(1 for v in orig_file_vulns if v.severity.value == "CRITICAL")
        result.high_before     = sum(1 for v in orig_file_vulns if v.severity.value == "HIGH")

        if not Path(patched_path).exists():
            result.error = f"Patched file not found: {patched_path}"
            return result

        # Re-run Phase 1+2 on patched file
        try:
            from core.phase1 import run_phase1
            from rules.engine import run_phase2

            p1 = run_phase1(patched_path, verbose=False)
            p2 = run_phase2(p1, verbose=False)

            after_vulns = list(p2.collection)
            result.vulns_after    = len(after_vulns)
            result.critical_after = sum(1 for v in after_vulns if v.severity.value == "CRITICAL")
            result.high_after     = sum(1 for v in after_vulns if v.severity.value == "HIGH")

            # Determine which original vulns are now gone
            after_rules = {(v.rule_name, v.line_start) for v in after_vulns}
            for v in orig_file_vulns:
                key = (v.rule_name, v.line_start)
                if key not in after_rules:
                    result.fixed_vuln_ids.append(v.vuln_id)
                else:
                    result.remaining_vuln_ids.append(v.vuln_id)

        except Exception as e:
            result.error = f"Re-analysis failed: {e}"

        return result