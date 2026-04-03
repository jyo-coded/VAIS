"""
core/standards_engine.py
────────────────────────
StandardsEngine that natively loads CWE mappings from the JSON DB to enrich vulnerabilities 
with actionable CVSS vectors, mitigation strategies, and code snippets.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

class StandardsEngine:
    """Security Standards Engine loading mapping properties from the database."""
    
    def __init__(self, db_path: str | Path = "data/standards_db.json"):
        self.db_path = Path(db_path)
        self.db = {}
        self._load_db()

    def _load_db(self) -> None:
        if not self.db_path.exists():
            log.warning(f"Standards database not found at {self.db_path}.")
            return
            
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                entries = json.load(f)
                for entry in entries:
                    cwe = entry.get("cwe_id")
                    if cwe:
                        self.db[cwe] = entry
        except json.JSONDecodeError as e:
            log.error(f"Standards JSON corrupt: {e}")

    def lookup(self, cwe_id: str) -> dict | None:
        """Fetch the fully documented DB entry for a given CWE ID."""
        return self.db.get(cwe_id)

    def format_citation(self, cwe_id: str) -> str:
        """
        Produce a one-line citation string connecting OWASP metrics with CERT checks.
        Example: "[CERT STR31-C] CVSS: 9.8 (CRITICAL) | A03:2021-Injection"
        """
        entry = self.lookup(cwe_id)
        if not entry:
            return f"Citation missing for {cwe_id}"
            
        rule = entry.get("cert_c_rule", "N/A")
        cvss = entry.get("cvss_v3_base", "N/A")
        sev  = entry.get("cvss_severity", "UNKNOWN")
        owasp= entry.get("owasp_category", "N/A")
        
        return f"[CERT {rule}] CVSS: {cvss} ({sev}) | {owasp}"

    def get_both_examples(self, cwe_id: str) -> tuple[str, str]:
        """Return (vulnerable_example, secure_example) pairs for documentation."""
        entry = self.lookup(cwe_id)
        if not entry:
            return ("No example available.", "No example available.")
            
        return entry.get("vulnerable_example", ""), entry.get("secure_example", "")
