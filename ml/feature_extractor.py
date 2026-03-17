"""
ml/feature_extractor.py
───────────────────────
Phase 3: Feature Extraction Module.

For every VulnObject, queries CodeContext and CallGraph to build
a numerical feature vector suitable for ML model input.

Features extracted (12 total):
  0.  cwe_cvss_score        — NVD average CVSS for this CWE (normalized 0-1)
  1.  severity_score        — Rule-assigned severity as number (0-1)
  2.  confidence            — Rule confidence score (0-1)
  3.  reachable_from_entry  — Is function reachable from entry point? (0/1)
  4.  has_extern_input      — Does function receive external input? (0/1)
  5.  call_depth            — Normalized call depth from entry point (0-1)
  6.  in_loop               — Is vulnerability inside a loop? (0/1)
  7.  pointer_ops           — Normalized pointer arithmetic ops in function (0-1)
  8.  unsafe_api_count      — Normalized count of unsafe API calls in function (0-1)
  9.  alloc_without_free    — Unfreed allocations in function (0/1)
  10. loop_depth            — Normalized max loop nesting depth (0-1)
  11. language_risk         — Language-level base risk score (0-1)

Output: numpy array X of shape (n_vulns, 12)
        synchronized list of VulnObjects (same order, same indices)
"""

from __future__ import annotations
import numpy as np
from typing import TYPE_CHECKING

from rules.vuln_object import VulnObject, Severity

if TYPE_CHECKING:
    from core.code_context import CodeContext
    from core.call_graph import CallGraph
    from ml.nvd_client import NVDClient

# ─── Feature metadata ────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "cwe_cvss_score",
    "severity_score",
    "confidence",
    "reachable_from_entry",
    "has_extern_input",
    "call_depth",
    "in_loop",
    "pointer_ops",
    "unsafe_api_count",
    "alloc_without_free",
    "loop_depth",
    "language_risk",
]

N_FEATURES = len(FEATURE_NAMES)

# Severity → numeric score
SEVERITY_SCORES = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH:     0.8,
    Severity.MEDIUM:   0.5,
    Severity.LOW:      0.2,
    Severity.INFO:     0.05,
}

# Language base risk (C highest — manual memory; Go medium; Python lowest for memory)
LANGUAGE_RISK = {
    "c":      1.0,
    "go":     0.6,
    "python": 0.5,
}

# Normalization caps — values above these are clipped to 1.0
CALL_DEPTH_CAP    = 10
POINTER_OPS_CAP   = 20
UNSAFE_API_CAP    = 15
LOOP_DEPTH_CAP    = 5

# Unsafe API sets per language (used to count unsafe calls in a function)
UNSAFE_APIS = {
    "c":      {
        "strcpy", "strcat", "sprintf", "gets", "scanf", "printf",
        "system", "popen", "exec", "memcpy", "memmove", "malloc",
        "free", "realloc",
    },
    "python": {
        "eval", "exec", "compile", "pickle.loads", "pickle.load",
        "subprocess.call", "subprocess.Popen", "os.system",
        "os.popen", "open", "input",
    },
    "go":     {
        "exec.Command", "unsafe.Pointer", "os.system",
        "fmt.Sprintf", "fmt.Fprintf",
    },
}


# ─── Feature Extractor ───────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Converts a list of VulnObjects + their CodeContexts into
    a numerical feature matrix for ML model input.

    Usage:
        extractor = FeatureExtractor(nvd_client)
        X, vulns = extractor.extract(vuln_collection, contexts, call_graphs)
    """

    def __init__(self, nvd_client: "NVDClient"):
        self.nvd = nvd_client

    def extract(
        self,
        vuln_collection,
        contexts:    list["CodeContext"],
        call_graphs: dict[str, "CallGraph"],
    ) -> tuple[np.ndarray, list[VulnObject]]:
        """
        Main extraction method.

        Returns:
            X:     np.ndarray of shape (n_vulns, N_FEATURES) — float32
            vulns: list[VulnObject] in same order as rows of X
        """
        # Build lookup: source_file → CodeContext
        ctx_map: dict[str, "CodeContext"] = {
            ctx.source_file: ctx for ctx in contexts
        }

        vulns = list(vuln_collection)
        if not vulns:
            return np.zeros((0, N_FEATURES), dtype=np.float32), []

        # Pre-fetch NVD scores for all CWEs in one batch
        cwe_ids = list({v.cwe.value for v in vulns})
        self.nvd.prefetch(cwe_ids)

        rows = []
        for vuln in vulns:
            ctx = ctx_map.get(vuln.source_file)
            cg  = call_graphs.get(vuln.source_file)
            row = self._extract_one(vuln, ctx, cg)
            rows.append(row)

        X = np.array(rows, dtype=np.float32)
        return X, vulns

    def _extract_one(
        self,
        vuln: VulnObject,
        ctx:  "CodeContext | None",
        cg:   "CallGraph | None",
    ) -> list[float]:
        """Extract feature vector for a single VulnObject."""

        fn_name = vuln.function_name
        fn_info = ctx.get_function(fn_name) if ctx else None

        # ── Feature 0: CWE CVSS score (NVD) ──────────────────────────────
        cwe_cvss = self.nvd.get_cvss_normalized(vuln.cwe.value)

        # ── Feature 1: Severity score ─────────────────────────────────────
        severity_score = SEVERITY_SCORES.get(vuln.severity, 0.5)

        # ── Feature 2: Rule confidence ────────────────────────────────────
        confidence = float(vuln.confidence)

        # ── Feature 3: Reachable from entry ──────────────────────────────
        reachable = 1.0 if vuln.reachable_from_entry else 0.0

        # ── Feature 4: External input ─────────────────────────────────────
        extern_input = 1.0 if vuln.has_extern_input else 0.0

        # ── Feature 5: Call depth (normalized) ───────────────────────────
        if cg and fn_name:
            raw_depth = cg.call_depth_from_entry(fn_name)
            call_depth = min(max(raw_depth, 0), CALL_DEPTH_CAP) / CALL_DEPTH_CAP
        else:
            call_depth = min(vuln.call_depth, CALL_DEPTH_CAP) / CALL_DEPTH_CAP

        # ── Feature 6: In loop ────────────────────────────────────────────
        in_loop = 1.0 if vuln.in_loop else 0.0

        # ── Feature 7: Pointer ops (normalized) ──────────────────────────
        raw_ptr = fn_info.pointer_ops if fn_info else 0
        pointer_ops = min(raw_ptr, POINTER_OPS_CAP) / POINTER_OPS_CAP

        # ── Feature 8: Unsafe API call count (normalized) ─────────────────
        unsafe_count = self._count_unsafe_apis(fn_name, vuln.language, ctx)
        unsafe_api_count = min(unsafe_count, UNSAFE_API_CAP) / UNSAFE_API_CAP

        # ── Feature 9: Unfreed allocations ───────────────────────────────
        if ctx:
            alloc_without_free = 1.0 if ctx.has_unfreed_allocations(fn_name) else 0.0
        else:
            alloc_without_free = 0.0

        # ── Feature 10: Loop depth (normalized) ──────────────────────────
        raw_loop = fn_info.loop_depth if fn_info else 0
        loop_depth = min(raw_loop, LOOP_DEPTH_CAP) / LOOP_DEPTH_CAP

        # ── Feature 11: Language risk ─────────────────────────────────────
        language_risk = LANGUAGE_RISK.get(vuln.language, 0.5)

        return [
            cwe_cvss,
            severity_score,
            confidence,
            reachable,
            extern_input,
            call_depth,
            in_loop,
            pointer_ops,
            unsafe_api_count,
            alloc_without_free,
            loop_depth,
            language_risk,
        ]

    def _count_unsafe_apis(
        self,
        fn_name:  str,
        language: str,
        ctx:      "CodeContext | None",
    ) -> int:
        """Count how many unsafe API calls appear in this function."""
        if not ctx:
            return 0
        unsafe_set = UNSAFE_APIS.get(language, set())
        return sum(
            1 for cs in ctx.call_sites
            if cs.caller == fn_name and cs.callee in unsafe_set
        )

    def feature_names(self) -> list[str]:
        return FEATURE_NAMES.copy()

    def to_dict(self, X: np.ndarray, vulns: list[VulnObject]) -> list[dict]:
        """
        Convert feature matrix to a list of human-readable dicts.
        Used for features.json output artifact.
        """
        result = []
        for i, vuln in enumerate(vulns):
            row = {
                "vuln_id":  vuln.vuln_id,
                "features": {
                    name: round(float(X[i, j]), 4)
                    for j, name in enumerate(FEATURE_NAMES)
                }
            }
            result.append(row)
        return result