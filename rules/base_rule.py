"""
rules/base_rule.py
──────────────────
Abstract base class for all vulnerability detection rules.

Every rule is a pure function:
    AST node + CodeContext → VulnObject | None

Rules are stateless — they never modify CodeContext.
Rules are registered in the RuleRegistry and dispatched by the engine.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.code_context import CodeContext, Language
    from rules.vuln_object import VulnObject, VulnCollection


class BaseRule(ABC):
    """
    Abstract base for all detection rules.

    Subclass this and implement `check()`.
    The engine calls `check()` for every relevant AST node.
    """

    # ── Rule metadata (override in subclass) ──────────────────────────────
    name:        str   = "unnamed_rule"
    languages:   list  = []          # Which languages this rule applies to
    node_types:  list  = []          # Which AST node types trigger this rule
    description: str   = ""

    @abstractmethod
    def check(
        self,
        node:        dict,           # AST node dict (from CodeContext.ast_json)
        context:     "CodeContext",
        collection:  "VulnCollection",
        source_lines: list[str],
    ) -> None:
        """
        Inspect `node` and add VulnObjects to `collection` if the rule fires.

        Args:
            node:         Current AST node as dict
            context:      Full CodeContext for structural queries
            collection:   VulnCollection to append findings to
            source_lines: Raw source lines for snippet extraction
        """
        ...

    # ── Shared utilities available to all rules ───────────────────────────

    def get_snippet(self, source_lines: list[str], start: int, end: int, context_lines: int = 1) -> str:
        """
        Extract source lines for a code snippet.
        start/end are 1-indexed line numbers.
        context_lines adds surrounding lines for readability.
        """
        total = len(source_lines)
        lo = max(0, start - 1 - context_lines)
        hi = min(total, end + context_lines)
        lines = source_lines[lo:hi]
        # Prefix with line numbers
        result = []
        for i, line in enumerate(lines, start=lo + 1):
            marker = ">>> " if start <= i <= end else "    "
            result.append(f"{marker}{i:4d} | {line.rstrip()}")
        return "\n".join(result)

    def get_line(self, source_lines: list[str], line_num: int) -> str:
        """Get a single source line (1-indexed). Returns empty string if out of range."""
        if 1 <= line_num <= len(source_lines):
            return source_lines[line_num - 1].strip()
        return ""

    def node_text(self, node: dict) -> str:
        """Extract text from an AST leaf node."""
        return node.get("text", "").strip()

    def node_type(self, node: dict) -> str:
        return node.get("type", "")

    def node_line(self, node: dict) -> int:
        """Return 1-indexed start line of a node."""
        start = node.get("start", [0, 0])
        return start[0] + 1

    def find_nodes(self, root: dict, node_type: str) -> list[dict]:
        """
        BFS/DFS search for all nodes of a given type under root.
        Used by rules that need to search subtrees.
        """
        results = []
        stack = [root]
        while stack:
            node = stack.pop()
            if node.get("type") == node_type:
                results.append(node)
            stack.extend(node.get("children", []))
        return results

    def find_text_in_children(self, node: dict, text: str) -> bool:
        """True if any child (recursively) contains the given text."""
        if text in self.node_text(node):
            return True
        return any(self.find_text_in_children(child, text) for child in node.get("children", []))

    def get_child_by_type(self, node: dict, child_type: str) -> Optional[dict]:
        """Get first direct child of given type."""
        for child in node.get("children", []):
            if child.get("type") == child_type:
                return child
        return None

    def __repr__(self) -> str:
        return f"Rule({self.name}, langs={self.languages})"