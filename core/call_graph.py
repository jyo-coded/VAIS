"""
core/call_graph.py
──────────────────
Phase 1, Step 2: Builds a directed call graph from a CodeContext.
Used by Phase 2 (reachability in rule evaluation) and Phase 3 (call depth features).

Graph is built once after parsing and attached to the session — not stored in CodeContext
itself to keep CodeContext JSON-serializable.
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional

import networkx as nx

from core.code_context import CodeContext


class CallGraph:
    """
    Directed graph where:
      nodes = function names (strings)
      edges = caller → callee (directed)

    Built from a single CodeContext (one file) or merged from multiple.
    """

    def __init__(self):
        self.graph: nx.DiGraph = nx.DiGraph()
        self._entry_points: set[str] = set()

    # ── Construction ──────────────────────────────────────────────────────

    @classmethod
    def from_context(cls, ctx: CodeContext) -> "CallGraph":
        """Build a CallGraph from a single parsed CodeContext."""
        cg = cls()
        cg._build(ctx)
        return cg

    @classmethod
    def from_contexts(cls, contexts: list[CodeContext]) -> "CallGraph":
        """Merge multiple CodeContexts (e.g., a whole project) into one graph."""
        cg = cls()
        for ctx in contexts:
            cg._build(ctx)
        return cg

    def _build(self, ctx: CodeContext) -> None:
        # Add all defined functions as nodes with metadata
        for fn_name, fn_info in ctx.functions.items():
            self.graph.add_node(fn_name, **{
                "language":     ctx.language.value,
                "file":         ctx.source_file,
                "start_line":   fn_info.start_line,
                "end_line":     fn_info.end_line,
                "is_entry":     fn_info.is_entry,
                "loop_depth":   fn_info.loop_depth,
                "pointer_ops":  fn_info.pointer_ops,
                "extern_input": fn_info.extern_input,
            })

        # Add edges from call sites
        for cs in ctx.call_sites:
            # Add callee node even if not defined in this file (external call)
            if cs.callee not in self.graph:
                self.graph.add_node(cs.callee, **{
                    "language":   ctx.language.value,
                    "file":       "external",
                    "is_entry":   False,
                    "external":   True,
                })
            self.graph.add_edge(cs.caller, cs.callee, line=cs.line)

        # Track entry points
        for ep in ctx.entry_points:
            self._entry_points.add(ep)

    # ── Queries ───────────────────────────────────────────────────────────

    def reachable_from_entry(self, function: str) -> bool:
        """
        True if `function` is reachable from any known entry point.
        Uses BFS via NetworkX descendants.
        """
        for ep in self._entry_points:
            if ep == function:
                return True
            if ep in self.graph:
                try:
                    if function in nx.descendants(self.graph, ep):
                        return True
                except nx.NetworkXError:
                    pass
        return False

    def call_depth_from_entry(self, function: str) -> int:
        """
        Shortest path length from any entry point to `function`.
        Returns 0 if it IS an entry point, -1 if unreachable.
        """
        if function in self._entry_points:
            return 0
        min_depth = float("inf")
        for ep in self._entry_points:
            if ep in self.graph and function in self.graph:
                try:
                    length = nx.shortest_path_length(self.graph, ep, function)
                    min_depth = min(min_depth, length)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    pass
        return int(min_depth) if min_depth != float("inf") else -1

    def callers_of(self, function: str) -> list[str]:
        """All functions that directly call `function`."""
        if function not in self.graph:
            return []
        return list(self.graph.predecessors(function))

    def callees_of(self, function: str) -> list[str]:
        """All functions directly called by `function`."""
        if function not in self.graph:
            return []
        return list(self.graph.successors(function))

    def all_paths_from_entry(self, function: str) -> list[list[str]]:
        """All simple paths from any entry point to `function`. Use carefully on large graphs."""
        paths = []
        for ep in self._entry_points:
            if ep in self.graph and function in self.graph:
                try:
                    for path in nx.all_simple_paths(self.graph, ep, function, cutoff=8):
                        paths.append(path)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    pass
        return paths

    def transitive_callees(self, function: str) -> set[str]:
        """All functions transitively called by `function` (descendants in graph)."""
        if function not in self.graph:
            return set()
        try:
            return nx.descendants(self.graph, function)
        except nx.NetworkXError:
            return set()

    def is_recursive(self, function: str) -> bool:
        """True if the function (directly or indirectly) calls itself."""
        return function in self.transitive_callees(function)

    def node_metadata(self, function: str) -> dict:
        """Return stored metadata for a function node."""
        return dict(self.graph.nodes.get(function, {}))

    # ── Export ────────────────────────────────────────────────────────────

    def save(self, path: str | Path) -> None:
        """Save graph in GML format (readable by Gephi, Cytoscape, etc.)"""
        nx.write_gml(self.graph, str(path))

    def to_dict(self) -> dict:
        """JSON-serializable representation."""
        return {
            "nodes": [
                {"id": n, **self.graph.nodes[n]}
                for n in self.graph.nodes
            ],
            "edges": [
                {"from": u, "to": v, **self.graph.edges[u, v]}
                for u, v in self.graph.edges
            ],
            "entry_points": list(self._entry_points),
            "stats": {
                "total_nodes": self.graph.number_of_nodes(),
                "total_edges": self.graph.number_of_edges(),
                "is_dag":      nx.is_directed_acyclic_graph(self.graph),
            }
        }

    @property
    def stats(self) -> dict:
        return {
            "functions":    self.graph.number_of_nodes(),
            "call_edges":   self.graph.number_of_edges(),
            "entry_points": list(self._entry_points),
            "is_dag":       nx.is_directed_acyclic_graph(self.graph),
        }

    def __repr__(self) -> str:
        return (
            f"CallGraph(nodes={self.graph.number_of_nodes()}, "
            f"edges={self.graph.number_of_edges()}, "
            f"entries={list(self._entry_points)})"
        )