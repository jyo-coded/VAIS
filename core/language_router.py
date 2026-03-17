"""
core/language_router.py
───────────────────────
Phase 1, Step 0: Sits before the parser.
Handles all three input modes:
  1. Single file      → vapt scan file.c
  2. Project folder   → vapt scan ./project --lang auto
  3. Manual override  → vapt scan ./project --lang c

Returns a list of (file_path, Language) tuples ready for the parser.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from core.code_context import Language

console = Console()

# Files/dirs to always skip
SKIP_PATTERNS = {
    "__pycache__", ".git", ".github", "node_modules",
    "vendor", "third_party", "build", "dist", ".venv",
    "venv", "env", ".mypy_cache", ".pytest_cache",
}

SUPPORTED_EXTENSIONS = {".c", ".h", ".py", ".go"}


class LanguageRouter:
    """
    Resolves input paths to a list of (file_path, Language) pairs.

    Usage:
        router = LanguageRouter(path="./project", lang_override="auto")
        targets = router.resolve()
        # → [("./project/main.c", Language.C), ("./project/util.py", Language.PYTHON), ...]
    """

    def __init__(
        self,
        path: str,
        lang_override: Optional[str] = None,   # "auto", "c", "python", "go", or None
        verbose: bool = True,
    ):
        self.path = Path(path).resolve()
        self.lang_override = lang_override
        self.verbose = verbose
        self._targets: list[tuple[Path, Language]] = []

    # ── Public ────────────────────────────────────────────────────────────

    def resolve(self) -> list[tuple[Path, Language]]:
        """Main entry point. Returns resolved (path, language) pairs."""
        if not self.path.exists():
            raise FileNotFoundError(f"Path does not exist: {self.path}")

        if self.path.is_file():
            self._targets = self._resolve_single_file(self.path)
        elif self.path.is_dir():
            self._targets = self._resolve_directory(self.path)
        else:
            raise ValueError(f"Path is neither file nor directory: {self.path}")

        if not self._targets:
            raise ValueError(
                f"No supported source files found at: {self.path}\n"
                f"Supported: {', '.join(SUPPORTED_EXTENSIONS)}"
            )

        if self.verbose:
            self._print_summary()

        return self._targets

    # ── Internal resolvers ────────────────────────────────────────────────

    def _resolve_single_file(self, file: Path) -> list[tuple[Path, Language]]:
        """Resolve a single file — manual override wins, else auto-detect."""
        lang = self._determine_language(file)
        if lang is None:
            raise ValueError(
                f"Cannot determine language for: {file.name}\n"
                f"Use --lang to specify manually."
            )
        return [(file, lang)]

    def _resolve_directory(self, directory: Path) -> list[tuple[Path, Language]]:
        """
        Walk directory recursively.
        Collect all supported source files.
        Apply language override if set, else auto-detect per file.
        """
        results: list[tuple[Path, Language]] = []

        for root, dirs, files in os.walk(directory):
            # Prune skip dirs in-place so os.walk doesn't recurse into them
            dirs[:] = [
                d for d in dirs
                if d not in SKIP_PATTERNS and not d.startswith(".")
            ]

            for filename in sorted(files):
                filepath = Path(root) / filename

                if filepath.suffix.lower() not in SUPPORTED_EXTENSIONS:
                    continue

                lang = self._determine_language(filepath)
                if lang is not None:
                    results.append((filepath, lang))

        return results

    def _determine_language(self, file: Path) -> Optional[Language]:
        """
        Language resolution priority:
          1. Manual override (--lang flag) — always wins
          2. File extension auto-detection
          3. None if unresolvable
        """
        # Manual override
        if self.lang_override and self.lang_override.lower() != "auto":
            try:
                return Language.from_string(self.lang_override)
            except ValueError:
                raise ValueError(
                    f"Invalid --lang value: '{self.lang_override}'. "
                    f"Choose from: c, python, go"
                )

        # Auto-detect from extension
        return Language.from_extension(file.suffix)

    # ── Display ───────────────────────────────────────────────────────────

    def _print_summary(self) -> None:
        """Print a rich summary table of resolved targets."""
        # Group by language
        by_lang: dict[str, int] = {}
        for _, lang in self._targets:
            by_lang[lang.value] = by_lang.get(lang.value, 0) + 1

        console.print()
        console.print(
            f"[bold cyan]⟦ Language Router ⟧[/bold cyan]  "
            f"[dim]resolved {len(self._targets)} file(s)[/dim]"
        )

        table = Table(
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            show_edge=True,
            padding=(0, 1),
        )
        table.add_column("File", style="white")
        table.add_column("Language", style="cyan", justify="center")
        table.add_column("Mode", style="dim", justify="center")

        mode = "manual" if (self.lang_override and self.lang_override != "auto") else "auto"
        lang_colors = {
            Language.C:      "cyan",
            Language.PYTHON: "yellow",
            Language.GO:     "blue",
        }

        for filepath, lang in self._targets:
            color = lang_colors.get(lang, "white")
            # Show path relative to scan root
            try:
                display = str(filepath.relative_to(self.path.parent))
            except ValueError:
                display = str(filepath)
            table.add_row(display, f"[{color}]{lang.value}[/{color}]", mode)

        console.print(table)

        # Summary line
        summary_parts = [f"[{c}]{lang}[/{c}]: {count}" for (lang, count), c in zip(
            by_lang.items(),
            ["cyan", "yellow", "blue", "green"]
        )]
        console.print(f"  [dim]Total:[/dim] {' · '.join(summary_parts)}")
        console.print()

    # ── Stats (used by Phase 1 parser to iterate) ─────────────────────────

    def targets_by_language(self) -> dict[Language, list[Path]]:
        """Group resolved targets by language."""
        result: dict[Language, list[Path]] = {}
        for path, lang in self._targets:
            result.setdefault(lang, []).append(path)
        return result

    def __len__(self) -> int:
        return len(self._targets)

    def __repr__(self) -> str:
        return f"LanguageRouter(path={self.path}, targets={len(self._targets)})"