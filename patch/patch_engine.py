"""
patch/patch_engine.py
─────────────────────
Phase 6: Patch Engine.

For each (vuln_id, strategy) decision from Phase 5:
  1. Locate the vulnerable line in the source file
  2. Look up the patch template for (CWE, strategy)
  3. Apply the template's patch_fn to generate fixed lines
  4. Write the patched file
  5. Generate a unified diff

Produces:
  - patched source file
  - unified diff (.diff)
  - PatchResult per vulnerability
"""

from __future__ import annotations
import difflib
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rules.vuln_object import VulnObject
from patch.template_library import get_template, PatchTemplate


@dataclass
class PatchResult:
    """Result of patching a single vulnerability."""
    vuln_id:      str
    strategy:     str
    cwe:          str
    source_file:  str
    line_patched: int
    success:      bool
    diff_lines:   list[str] = field(default_factory=list)
    error:        str       = ""
    description:  str       = ""

    def to_dict(self) -> dict:
        return {
            "vuln_id":      self.vuln_id,
            "strategy":     self.strategy,
            "cwe":          self.cwe,
            "source_file":  self.source_file,
            "line_patched": self.line_patched,
            "success":      self.success,
            "error":        self.error,
            "description":  self.description,
            "diff_preview": self.diff_lines[:20],
        }


class PatchEngine:
    """
    Applies patch templates to source files.

    Works file-by-file: gathers all patches for a file,
    applies them in reverse line order (so line numbers stay valid),
    then writes the result and generates a diff.
    """

    def apply_all(
        self,
        decisions:   list[tuple[str, str]],
        scored_vulns: list[VulnObject],
        output_dir:  str | Path,
    ) -> tuple[list[PatchResult], dict[str, str]]:
        """
        Apply all patch decisions.

        Returns:
            patch_results:  list of PatchResult per decision
            patched_files:  dict of {original_path: patched_path}
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # Index vulns by ID
        vuln_map = {v.vuln_id: v for v in scored_vulns}

        # Group decisions by source file
        file_decisions: dict[str, list[tuple[VulnObject, str]]] = {}
        for vuln_id, strategy in decisions:
            vuln = vuln_map.get(vuln_id)
            if not vuln:
                continue
            src = vuln.source_file
            file_decisions.setdefault(src, []).append((vuln, strategy))

        patch_results: list[PatchResult] = []
        patched_files: dict[str, str]    = {}

        for src_path, vuln_strategy_pairs in file_decisions.items():
            results, patched_path = self._patch_file(
                src_path, vuln_strategy_pairs, out
            )
            patch_results.extend(results)
            if patched_path:
                patched_files[src_path] = patched_path

        return patch_results, patched_files

    def _patch_file(
        self,
        src_path:           str,
        vuln_strategy_pairs: list[tuple[VulnObject, str]],
        output_dir:         Path,
    ) -> tuple[list[PatchResult], Optional[str]]:
        """Patch all vulnerabilities in a single source file."""

        src = Path(src_path)
        if not src.exists():
            return [PatchResult(
                vuln_id=p[0].vuln_id, strategy=p[1],
                cwe=p[0].cwe.value, source_file=src_path,
                line_patched=0, success=False,
                error=f"Source file not found: {src_path}",
            ) for p in vuln_strategy_pairs], None

        # Read original lines
        with open(src, "r", encoding="utf-8", errors="replace") as f:
            original_lines = f.readlines()

        # Ensure every line ends with \n
        lines = list(original_lines)
        for i, l in enumerate(lines):
            if l and not l.endswith("\n"):
                lines[i] = l + "\n"

        results:    list[PatchResult] = []
        applied:    list[PatchResult] = []

        # Sort by line number descending — apply bottom-up to preserve indices
        sorted_pairs = sorted(
            vuln_strategy_pairs,
            key=lambda x: x[0].line_start,
            reverse=True,
        )

        for vuln, strategy in sorted_pairs:
            result = self._apply_one_patch(vuln, strategy, lines)
            results.append(result)
            if result.success:
                applied.append(result)

        # Write patched file
        stem      = src.stem
        suffix    = src.suffix
        out_name  = f"{stem}_patched{suffix}"
        out_path  = output_dir / out_name

        with open(out_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Generate unified diff
        diff_lines = list(difflib.unified_diff(
            original_lines,
            lines,
            fromfile=f"a/{src.name}",
            tofile=f"b/{out_name}",
            lineterm="",
        ))

        # Save diff file
        diff_path = output_dir / f"{stem}.diff"
        with open(diff_path, "w", encoding="utf-8") as f:
            f.write("\n".join(diff_lines))

        # Attach diff to results
        for r in results:
            if r.success:
                r.diff_lines = diff_lines

        return results, str(out_path)

    def _apply_one_patch(
        self,
        vuln:     VulnObject,
        strategy: str,
        lines:    list[str],
    ) -> PatchResult:
        """
        Locate the vulnerable line and apply the patch template.
        Modifies `lines` in-place.
        """
        result = PatchResult(
            vuln_id=vuln.vuln_id,
            strategy=strategy,
            cwe=vuln.cwe.value,
            source_file=vuln.source_file,
            line_patched=vuln.line_start,
            success=False,
        )

        # Find the vulnerable line (1-indexed → 0-indexed)
        target_idx = vuln.line_start - 1
        if target_idx < 0 or target_idx >= len(lines):
            result.error = f"Line {vuln.line_start} out of range (file has {len(lines)} lines)"
            return result

        target_line = lines[target_idx]

        # Get template with line content for smarter matching
        template = get_template(vuln.cwe.value, strategy, target_line)
        if not template:
            result.error = f"No template found for ({vuln.cwe.value}, {strategy})"
            return result

        result.description = template.description

        # Check template matches this line
        if not template.match_fn(target_line):
            # Try nearby lines (±3) — AST line numbers can be off by a few
            found_idx = None
            for delta in range(1, 4):
                for offset in [delta, -delta]:
                    check_idx = target_idx + offset
                    if 0 <= check_idx < len(lines):
                        if template.match_fn(lines[check_idx]):
                            found_idx = check_idx
                            break
                if found_idx is not None:
                    break

            if found_idx is None:
                result.error = (
                    f"Pattern for {strategy} not found near line {vuln.line_start}. "
                    f"Line content: {target_line.strip()[:80]}"
                )
                return result

            target_idx  = found_idx
            target_line = lines[target_idx]

        # Apply the patch
        try:
            patched_lines = template.patch_fn(
                target_line,
                vuln.function_name or "",
                lines,
                target_idx,
            )

            if patched_lines and patched_lines != [target_line]:
                lines[target_idx : target_idx + 1] = patched_lines
                result.success      = True
                result.line_patched = target_idx + 1
            else:
                # Line already patched by an earlier pass (duplicate rule firing
                # on the same source line) — treat as success, nothing to do.
                result.success     = True
                result.description = (result.description or template.description) +                                      " (already applied — duplicate finding)"

        except Exception as e:
            result.error = f"Patch function failed: {e}"

        return result