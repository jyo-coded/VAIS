"""
rules/vuln_object.py
────────────────────
The output contract of Phase 2.
Every detected vulnerability is a VulnObject.
Phase 3 (feature extraction) and Phase 5 (agent) consume this directly.

Never mutated after Phase 2 finalizes — Phase 4 attaches scores via ScoredVuln.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import json


# ─── CWE Registry ────────────────────────────────────────────────────────────

class CWE(str, Enum):
    """Common Weakness Enumeration IDs covered by this system."""
    # Memory safety — C
    BUFFER_OVERFLOW     = "CWE-120"   # Classic buffer overflow
    STACK_OVERFLOW      = "CWE-121"   # Stack-based buffer overflow
    HEAP_OVERFLOW       = "CWE-122"   # Heap-based buffer overflow
    USE_AFTER_FREE      = "CWE-416"   # Use after free
    DOUBLE_FREE         = "CWE-415"   # Double free
    NULL_DEREF          = "CWE-476"   # NULL pointer dereference
    MISSING_BOUNDS      = "CWE-125"   # Out-of-bounds read

    # Input handling — all languages
    FORMAT_STRING       = "CWE-134"   # Uncontrolled format string
    COMMAND_INJECTION   = "CWE-78"    # OS command injection
    PATH_TRAVERSAL      = "CWE-22"    # Path traversal
    UNSAFE_INPUT        = "CWE-20"    # Improper input validation

    # Python-specific
    CODE_INJECTION      = "CWE-95"    # eval/exec injection
    UNSAFE_DESERIALIZE  = "CWE-502"   # Pickle / unsafe deserialization
    HARDCODED_SECRET    = "CWE-798"   # Hardcoded credentials

    # Go-specific
    UNCHECKED_ERROR     = "CWE-390"   # Error result ignored
    RACE_CONDITION      = "CWE-362"   # Concurrent access without sync
    UNSAFE_POINTER      = "CWE-242"   # Use of inherently unsafe function


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class VulnStatus(str, Enum):
    OPEN      = "OPEN"       # Detected, not yet patched
    PATCHED   = "PATCHED"    # Patch applied and verified
    PARTIAL   = "PARTIAL"    # Patch applied but not fully resolved
    IGNORED   = "IGNORED"    # Agent decided not a real finding
    FP        = "FALSE_POS"  # Marked as false positive


# ─── Core VulnObject ─────────────────────────────────────────────────────────

@dataclass
class VulnObject:
    """
    Represents a single detected vulnerability.
    Created by Phase 2 rule engine.
    Enriched by Phase 3 (features) and Phase 4 (ML scores).
    Acted on by Phase 5 (agent).
    """

    # Identity
    vuln_id:        str                      # Unique ID: e.g. "VAPT-C-001"
    cwe:            CWE                      # CWE classification
    rule_name:      str                      # Which rule fired: e.g. "strcpy_overflow"

    # Location
    source_file:    str
    language:       str                      # "c", "python", "go"
    function_name:  str
    line_start:     int
    line_end:       int

    # Description
    title:          str                      # Short: "Buffer Overflow via strcpy"
    description:    str                      # Full explanation
    code_snippet:   str                      # The offending code lines

    # Risk (set by Phase 2 heuristics, refined by Phase 4 ML)
    severity:       Severity                 = Severity.MEDIUM
    confidence:     float                    = 0.5    # 0.0 – 1.0

    # Context flags (used by Phase 3 feature extraction)
    reachable_from_entry: bool              = False
    has_extern_input:     bool              = False
    call_depth:           int               = 0
    in_loop:              bool              = False

    # ML scores (attached by Phase 4)
    exploit_prob:         Optional[float]   = None   # 0.0 – 1.0
    risk_score:           Optional[float]   = None   # composite
    ml_severity:          Optional[Severity] = None

    # Patch info (attached by Phase 6)
    patch_strategy:       Optional[str]     = None
    patch_applied:        Optional[bool]    = None
    patch_diff:           Optional[str]     = None

    # Status
    status:               VulnStatus        = VulnStatus.OPEN
    agent_notes:          list[str]         = field(default_factory=list)

    # ── Convenience ───────────────────────────────────────────────────────

    @property
    def is_high_risk(self) -> bool:
        """True if severity is HIGH or CRITICAL."""
        return self.severity in (Severity.CRITICAL, Severity.HIGH)

    @property
    def composite_risk(self) -> float:
        """
        Best available risk score.
        Uses ML score if available, falls back to confidence-based heuristic.
        """
        if self.risk_score is not None:
            return self.risk_score
        severity_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH:     0.8,
            Severity.MEDIUM:   0.5,
            Severity.LOW:      0.2,
            Severity.INFO:     0.05,
        }
        base = severity_weights.get(self.severity, 0.5)
        return round(base * self.confidence, 4)

    @property
    def location_str(self) -> str:
        return f"{self.source_file}:{self.line_start}"

    def add_agent_note(self, note: str) -> None:
        self.agent_notes.append(note)

    # ── Serialization ─────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "vuln_id":             self.vuln_id,
            "cwe":                 self.cwe.value,
            "rule_name":           self.rule_name,
            "source_file":         self.source_file,
            "language":            self.language,
            "function_name":       self.function_name,
            "line_start":          self.line_start,
            "line_end":            self.line_end,
            "title":               self.title,
            "description":         self.description,
            "code_snippet":        self.code_snippet,
            "severity":            self.severity.value,
            "confidence":          self.confidence,
            "reachable_from_entry": self.reachable_from_entry,
            "has_extern_input":    self.has_extern_input,
            "call_depth":          self.call_depth,
            "in_loop":             self.in_loop,
            "exploit_prob":        self.exploit_prob,
            "risk_score":          self.risk_score,
            "ml_severity":         self.ml_severity.value if self.ml_severity else None,
            "patch_strategy":      self.patch_strategy,
            "patch_applied":       self.patch_applied,
            "status":              self.status.value,
            "agent_notes":         self.agent_notes,
            "composite_risk":      self.composite_risk,
        }

    def __repr__(self) -> str:
        return (
            f"VulnObject({self.vuln_id} | {self.cwe.value} | "
            f"{self.severity.value} | {self.function_name}:{self.line_start})"
        )


# ─── Collection helper ───────────────────────────────────────────────────────

class VulnCollection:
    """
    Ordered, deduplicated list of VulnObjects.
    Output contract of Phase 2 — input to Phase 3.
    """

    def __init__(self):
        self._vulns: list[VulnObject] = []
        self._id_counter: dict[str, int] = {}

    def add(self, vuln: VulnObject) -> None:
        # Deduplicate: same rule + same function + same line
        for existing in self._vulns:
            if (existing.rule_name == vuln.rule_name
                    and existing.function_name == vuln.function_name
                    and existing.line_start == vuln.line_start):
                return  # already recorded
        self._vulns.append(vuln)

    def generate_id(self, language: str) -> str:
        """Generate a sequential unique ID per language."""
        lang = language.upper()
        self._id_counter[lang] = self._id_counter.get(lang, 0) + 1
        return f"VAPT-{lang}-{self._id_counter[lang]:03d}"

    def sorted_by_risk(self) -> list[VulnObject]:
        return sorted(self._vulns, key=lambda v: v.composite_risk, reverse=True)

    def by_severity(self, severity: Severity) -> list[VulnObject]:
        return [v for v in self._vulns if v.severity == severity]

    def by_cwe(self, cwe: CWE) -> list[VulnObject]:
        return [v for v in self._vulns if v.cwe == cwe]

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(
                {"total": len(self._vulns),
                 "vulnerabilities": [v.to_dict() for v in self.sorted_by_risk()]},
                f, indent=2
            )

    def summary(self) -> dict:
        from collections import Counter
        sev_counts = Counter(v.severity.value for v in self._vulns)
        return {
            "total":    len(self._vulns),
            "critical": sev_counts.get("CRITICAL", 0),
            "high":     sev_counts.get("HIGH", 0),
            "medium":   sev_counts.get("MEDIUM", 0),
            "low":      sev_counts.get("LOW", 0),
            "by_cwe":   dict(Counter(v.cwe.value for v in self._vulns)),
            "by_lang":  dict(Counter(v.language for v in self._vulns)),
        }

    def __len__(self) -> int:
        return len(self._vulns)

    def __iter__(self):
        return iter(self._vulns)

    def __repr__(self) -> str:
        s = self.summary()
        return (f"VulnCollection(total={s['total']}, "
                f"critical={s['critical']}, high={s['high']}, "
                f"medium={s['medium']}, low={s['low']})")