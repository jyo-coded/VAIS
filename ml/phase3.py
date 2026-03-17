"""
ml/phase3.py
────────────
Phase 3 Orchestrator — Feature Extraction.

Consumes: Phase2Result (VulnCollection + Phase1Result for CodeContexts)
Produces: Phase3Result containing:
          - X: np.ndarray (feature matrix)
          - vulns: List[VulnObject] (synchronized with X rows)
          - features.json artifact
"""

from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Optional

import numpy as np
from rich.console import Console
from rich.table import Table

from ml.nvd_client import NVDClient
from ml.feature_extractor import FeatureExtractor, FEATURE_NAMES, N_FEATURES

console = Console()


# ─── Phase 3 Result ──────────────────────────────────────────────────────────

class Phase3Result:
    """
    Output contract of Phase 3.
    Phase 4 (ML model) receives exactly this object.
    """

    def __init__(self):
        self.X:           np.ndarray        = np.zeros((0, N_FEATURES), dtype=np.float32)
        self.vulns:       list              = []
        self.errors:      list[str]         = []
        self.duration_s:  float             = 0.0
        self.nvd_online:  bool              = False

    @property
    def n_vulns(self) -> int:
        return len(self.vulns)

    @property
    def n_features(self) -> int:
        return N_FEATURES

    def save(self, output_dir: str | Path) -> None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # Save feature matrix as JSON
        extractor = FeatureExtractor(NVDClient(use_api=False))
        feature_dicts = extractor.to_dict(self.X, self.vulns)

        with open(out / "features.json", "w") as f:
            json.dump({
                "n_vulns":       self.n_vulns,
                "n_features":    self.n_features,
                "feature_names": FEATURE_NAMES,
                "nvd_online":    self.nvd_online,
                "features":      feature_dicts,
            }, f, indent=2)

        # Save raw numpy array
        np.save(str(out / "feature_matrix.npy"), self.X)

        console.print(f"[dim]  Phase 3 artifacts saved → {out}/[/dim]")

    def summary(self) -> dict:
        return {
            "n_vulns":    self.n_vulns,
            "n_features": self.n_features,
            "nvd_online": self.nvd_online,
            "has_nans":   bool(np.isnan(self.X).any()) if self.n_vulns > 0 else False,
            "duration_s": round(self.duration_s, 3),
            "errors":     self.errors,
        }

    def __repr__(self) -> str:
        return (f"Phase3Result(vulns={self.n_vulns}, "
                f"features={self.n_features}, "
                f"shape={self.X.shape})")


# ─── Phase 3 Entry Point ─────────────────────────────────────────────────────

def run_phase3(
    phase2_result,
    phase1_result,
    output_dir:  Optional[str] = None,
    use_nvd_api: bool          = False,
    verbose:     bool          = True,
) -> Phase3Result:
    """
    Run Phase 3 end-to-end.

    Args:
        phase2_result:  Phase2Result from Phase 2
        phase1_result:  Phase1Result from Phase 1 (for CodeContexts + CallGraphs)
        output_dir:     If set, saves features.json and feature_matrix.npy here
        use_nvd_api:    Whether to call NVD API for real CVSS scores
                        (False = use hardcoded defaults, faster, works offline)
        verbose:        Print progress to console

    Returns:
        Phase3Result — typed output contract consumed by Phase 4
    """
    start  = time.time()
    result = Phase3Result()

    if verbose:
        console.print()
        console.rule(
            "[bold yellow]PHASE 3 — Feature Extraction[/bold yellow]",
            style="yellow"
        )

    # ── Check we have vulns to process ───────────────────────────────────
    if len(phase2_result.collection) == 0:
        console.print("[yellow]  No vulnerabilities to extract features from.[/yellow]")
        result.duration_s = time.time() - start
        return result

    # ── Init NVD client ───────────────────────────────────────────────────
    if verbose:
        api_status = "[cyan]NVD API[/cyan]" if use_nvd_api else "[dim]offline defaults[/dim]"
        console.print(f"  CVSS source: {api_status}")

    nvd_client = NVDClient(use_api=use_nvd_api)

    # Quick connectivity check
    if use_nvd_api:
        try:
            import requests
            r = requests.get("https://services.nvd.nist.gov", timeout=3)
            result.nvd_online = r.status_code < 500
        except Exception:
            result.nvd_online = False
            if verbose:
                console.print(
                    "  [yellow]⚠ NVD API unreachable — using offline defaults[/yellow]"
                )
            nvd_client = NVDClient(use_api=False)
    else:
        result.nvd_online = False

    # ── Extract features ──────────────────────────────────────────────────
    extractor = FeatureExtractor(nvd_client)

    try:
        X, vulns = extractor.extract(
            vuln_collection=phase2_result.collection,
            contexts=phase1_result.contexts,
            call_graphs=phase1_result.call_graphs,
        )
        result.X     = X
        result.vulns = vulns

    except Exception as e:
        result.errors.append(f"Feature extraction failed: {e}")
        if verbose:
            console.print(f"[red]✗ Feature extraction error: {e}[/red]")
        result.duration_s = time.time() - start
        return result

    # ── Validate — no NaNs ───────────────────────────────────────────────
    if np.isnan(result.X).any():
        nan_count = int(np.isnan(result.X).sum())
        result.errors.append(f"Feature matrix contains {nan_count} NaN values")
        # Replace NaNs with 0.0 — safe default
        result.X = np.nan_to_num(result.X, nan=0.0)
        if verbose:
            console.print(
                f"  [yellow]⚠ Replaced {nan_count} NaN values with 0.0[/yellow]"
            )

    # ── Save artifacts ────────────────────────────────────────────────────
    if output_dir:
        result.save(output_dir)

    result.duration_s = time.time() - start

    if verbose:
        _print_phase3_summary(result, extractor)

    return result


def _print_phase3_summary(result: Phase3Result, extractor: FeatureExtractor) -> None:
    """Print a rich Phase 3 summary with feature statistics."""

    s = result.summary()

    # Stats table
    stats_table = Table(show_header=False, border_style="dim", padding=(0, 2))
    stats_table.add_column("Key",   style="dim")
    stats_table.add_column("Value", style="white")

    stats_table.add_row("Vulnerabilities",  str(s["n_vulns"]))
    stats_table.add_row("Features/vector",  str(s["n_features"]))
    stats_table.add_row("Matrix shape",     f"({s['n_vulns']} × {s['n_features']})")
    stats_table.add_row("NaN values",       "[red]Yes[/red]" if s["has_nans"] else "[green]None[/green]")
    stats_table.add_row("CVSS source",      "NVD API" if s["nvd_online"] else "Offline defaults")
    stats_table.add_row("Duration",         f"{s['duration_s']}s")

    console.print(stats_table)

    # Feature value ranges
    if result.n_vulns > 0:
        feature_table = Table(
            title="Feature Statistics",
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            padding=(0, 2),
        )
        feature_table.add_column("Feature",  style="cyan")
        feature_table.add_column("Min",      justify="right")
        feature_table.add_column("Max",      justify="right")
        feature_table.add_column("Mean",     justify="right")

        for j, name in enumerate(FEATURE_NAMES):
            col = result.X[:, j]
            feature_table.add_row(
                name,
                f"{col.min():.3f}",
                f"{col.max():.3f}",
                f"{col.mean():.3f}",
            )

        console.print(feature_table)

    console.print(
        f"\n[green]✓ Phase 3 complete[/green] "
        f"[dim]→ Feature matrix ready for Phase 4[/dim]\n"
    )