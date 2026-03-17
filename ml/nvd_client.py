"""
ml/nvd_client.py
────────────────
NVD (National Vulnerability Database) REST API client.
Fetches real CVSS scores for CWE IDs to use as features in Phase 3.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
No API key required for basic usage (rate limited to 5 req/30s).

Results are cached in memory to avoid redundant API calls during a scan.
"""

from __future__ import annotations
import time
import requests
from typing import Optional

# ─── Default CVSS scores per CWE (fallback if API unavailable) ───────────────
# Based on historical NVD averages — keeps system working fully offline

CWE_CVSS_DEFAULTS: dict[str, float] = {
    "CWE-120": 7.5,   # Buffer overflow
    "CWE-121": 7.8,   # Stack overflow
    "CWE-122": 7.8,   # Heap overflow
    "CWE-125": 6.5,   # Out-of-bounds read
    "CWE-134": 7.5,   # Format string
    "CWE-20":  5.3,   # Improper input validation
    "CWE-22":  6.5,   # Path traversal
    "CWE-242": 5.5,   # Unsafe function
    "CWE-362": 7.0,   # Race condition
    "CWE-390": 4.3,   # Ignored error
    "CWE-401": 5.5,   # Memory leak
    "CWE-415": 8.1,   # Double free
    "CWE-416": 8.1,   # Use after free
    "CWE-476": 6.5,   # NULL dereference
    "CWE-502": 9.1,   # Unsafe deserialization
    "CWE-617": 4.3,   # Reachable assertion
    "CWE-78":  9.8,   # Command injection
    "CWE-798": 7.5,   # Hardcoded credentials
    "CWE-95":  9.8,   # Code injection
}

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 8    # seconds
RATE_LIMIT_DELAY = 6   # seconds between requests (NVD: 5 req/30s)


class NVDClient:
    """
    Fetches average CVSS scores for a given CWE from NVD.
    Falls back to hardcoded defaults if API is unavailable.

    Usage:
        client = NVDClient(use_api=True)
        score = client.get_cvss_score("CWE-78")
        # → 9.8
    """

    def __init__(self, use_api: bool = True):
        self.use_api = use_api
        self._cache: dict[str, float] = {}
        self._last_request: float = 0.0

    def get_cvss_score(self, cwe_id: str) -> float:
        """
        Get average CVSS score for a CWE ID.
        Returns a float between 0.0 and 10.0.

        Priority:
          1. Memory cache (fastest)
          2. NVD API (if use_api=True and network available)
          3. Hardcoded defaults (always available)
        """
        # Normalize: "CWE-78" or "78" → "CWE-78"
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        # 1. Cache hit
        if cwe_id in self._cache:
            return self._cache[cwe_id]

        # 2. Try API
        if self.use_api:
            score = self._fetch_from_nvd(cwe_id)
            if score is not None:
                self._cache[cwe_id] = score
                return score

        # 3. Fallback to defaults
        score = CWE_CVSS_DEFAULTS.get(cwe_id, 5.0)
        self._cache[cwe_id] = score
        return score

    def get_cvss_normalized(self, cwe_id: str) -> float:
        """Return CVSS score normalized to [0.0, 1.0] range."""
        return round(self.get_cvss_score(cwe_id) / 10.0, 4)

    def _fetch_from_nvd(self, cwe_id: str) -> Optional[float]:
        """
        Query NVD API for CVEs matching this CWE and compute average CVSS.
        Returns None if request fails or no data found.
        """
        # Respect rate limit
        elapsed = time.time() - self._last_request
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)

        try:
            params = {
                "cweId": cwe_id,
                "resultsPerPage": 20,
                "startIndex": 0,
            }
            headers = {"Accept": "application/json"}

            resp = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            self._last_request = time.time()

            if resp.status_code != 200:
                return None

            data = resp.json()
            vulns = data.get("vulnerabilities", [])

            if not vulns:
                return None

            # Extract CVSS v3 scores, fall back to v2
            scores = []
            for item in vulns:
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})

                # Try CVSS v3.1 first
                v31 = metrics.get("cvssMetricV31", [])
                if v31:
                    score = v31[0].get("cvssData", {}).get("baseScore")
                    if score:
                        scores.append(float(score))
                        continue

                # Try CVSS v3.0
                v30 = metrics.get("cvssMetricV30", [])
                if v30:
                    score = v30[0].get("cvssData", {}).get("baseScore")
                    if score:
                        scores.append(float(score))
                        continue

                # Fall back to CVSS v2
                v2 = metrics.get("cvssMetricV2", [])
                if v2:
                    score = v2[0].get("cvssData", {}).get("baseScore")
                    if score:
                        scores.append(float(score))

            if not scores:
                return None

            avg = sum(scores) / len(scores)
            return round(avg, 2)

        except Exception:
            return None

    def prefetch(self, cwe_ids: list[str]) -> None:
        """
        Pre-fetch CVSS scores for a list of CWEs in one batch.
        Useful to warm the cache before feature extraction.
        """
        for cwe_id in set(cwe_ids):
            self.get_cvss_score(cwe_id)

    def cache_summary(self) -> dict:
        return {
            "cached_cwes": list(self._cache.keys()),
            "total_cached": len(self._cache),
        }