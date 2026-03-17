"""
core/code_context.py
────────────────────
The central data contract for Phase 1.
Every downstream phase consumes CodeContext — nothing else touches raw AST.

Schema is intentionally frozen after Phase 1 completes.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import json


# ─── Supported Languages ────────────────────────────────────────────────────

class Language(str, Enum):
    C      = "c"
    PYTHON = "python"
    GO     = "go"

    @classmethod
    def from_extension(cls, ext: str) -> Optional["Language"]:
        return {
            ".c":  cls.C,
            ".h":  cls.C,
            ".py": cls.PYTHON,
            ".go": cls.GO,
        }.get(ext.lower())

    @classmethod
    def from_string(cls, s: str) -> "Language":
        s = s.lower().strip()
        aliases = {"c": cls.C, "python": cls.PYTHON, "py": cls.PYTHON, "go": cls.GO, "golang": cls.GO}
        if s not in aliases:
            raise ValueError(f"Unsupported language: '{s}'. Choose from: c, python, go")
        return aliases[s]


# ─── Fine-grained AST node types ────────────────────────────────────────────

@dataclass
class FunctionInfo:
    """Represents a single function/method definition."""
    name:         str
    start_line:   int
    end_line:     int
    params:       list[str]          = field(default_factory=list)
    return_type:  Optional[str]      = None
    is_entry:     bool               = False   # main(), init(), exported symbol
    calls:        list[str]          = field(default_factory=list)   # functions this calls
    pointer_ops:  int                = 0       # count of pointer arithmetic ops
    loop_depth:   int                = 0       # max nesting depth of loops
    extern_input: bool               = False   # reads from stdin / argv / network


@dataclass
class AllocationSite:
    """Tracks memory allocation and its corresponding free site (if found)."""
    function:     str
    line:         int
    alloc_type:   str                # malloc, calloc, realloc, new, make
    freed:        bool               = False
    free_line:    Optional[int]      = None


@dataclass
class VariableScope:
    """Tracks a variable's declaration and its scope boundaries."""
    name:         str
    var_type:     str
    function:     str
    declared_line: int
    is_pointer:   bool               = False
    is_array:     bool               = False
    array_size:   Optional[int]      = None    # None = dynamic / unknown


@dataclass
class CallSite:
    """A single function call occurrence in the code."""
    caller:       str
    callee:       str
    line:         int
    args:         list[str]          = field(default_factory=list)


# ─── The Core Contract ───────────────────────────────────────────────────────

@dataclass
class CodeContext:
    """
    The single output of Phase 1.
    All downstream phases (2–7) consume only this object + its JSON export.
    Never mutated after Phase 1 finalizes it.
    """

    # Identity
    source_file:    str
    language:       Language
    total_lines:    int

    # Structural inventory
    functions:      dict[str, FunctionInfo]   = field(default_factory=dict)
    call_sites:     list[CallSite]            = field(default_factory=list)
    allocations:    list[AllocationSite]      = field(default_factory=list)
    variables:      list[VariableScope]       = field(default_factory=list)

    # Entry points — Phase 2 uses these for reachability analysis
    entry_points:   list[str]                 = field(default_factory=list)

    # Raw AST — Phase 2 rule engine walks this directly
    ast_json:       Optional[dict]            = field(default=None, repr=False)

    # Metadata
    parse_errors:   list[str]                 = field(default_factory=list)
    parse_success:  bool                      = True

    # ── Convenience queries used by Phase 2 & 3 ──────────────────────────

    def get_function(self, name: str) -> Optional[FunctionInfo]:
        return self.functions.get(name)

    def get_callers_of(self, name: str) -> list[str]:
        """Return all functions that call the given function."""
        return [cs.caller for cs in self.call_sites if cs.callee == name]

    def get_callees_of(self, name: str) -> list[str]:
        """Return all functions called by the given function."""
        return [cs.callee for cs in self.call_sites if cs.caller == name]

    def get_allocations_in(self, function: str) -> list[AllocationSite]:
        return [a for a in self.allocations if a.function == function]

    def has_unfreed_allocations(self, function: str) -> bool:
        return any(not a.freed for a in self.get_allocations_in(function))

    def get_pointers_in(self, function: str) -> list[VariableScope]:
        return [v for v in self.variables if v.function == function and v.is_pointer]

    def function_call_depth(self, name: str, visited: Optional[set] = None) -> int:
        """Recursively compute max call depth from a function."""
        if visited is None:
            visited = set()
        if name in visited:
            return 0
        visited.add(name)
        callees = self.get_callees_of(name)
        if not callees:
            return 0
        return 1 + max(self.function_call_depth(c, visited) for c in callees)

    def is_reachable_from_entry(self, function: str) -> bool:
        """Check if a function is reachable from any entry point via BFS."""
        visited = set()
        queue = list(self.entry_points)
        while queue:
            current = queue.pop(0)
            if current == function:
                return True
            if current not in visited:
                visited.add(current)
                queue.extend(self.get_callees_of(current))
        return function in self.entry_points

    # ── Serialization ─────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialize to JSON-safe dict for ast.json output."""
        return {
            "source_file":   self.source_file,
            "language":      self.language.value,
            "total_lines":   self.total_lines,
            "parse_success": self.parse_success,
            "parse_errors":  self.parse_errors,
            "entry_points":  self.entry_points,
            "functions": {
                name: {
                    "start_line":   f.start_line,
                    "end_line":     f.end_line,
                    "params":       f.params,
                    "return_type":  f.return_type,
                    "is_entry":     f.is_entry,
                    "calls":        f.calls,
                    "pointer_ops":  f.pointer_ops,
                    "loop_depth":   f.loop_depth,
                    "extern_input": f.extern_input,
                }
                for name, f in self.functions.items()
            },
            "call_sites": [
                {"caller": cs.caller, "callee": cs.callee,
                 "line": cs.line, "args": cs.args}
                for cs in self.call_sites
            ],
            "allocations": [
                {"function": a.function, "line": a.line,
                 "alloc_type": a.alloc_type, "freed": a.freed,
                 "free_line": a.free_line}
                for a in self.allocations
            ],
            "variables": [
                {"name": v.name, "var_type": v.var_type,
                 "function": v.function, "declared_line": v.declared_line,
                 "is_pointer": v.is_pointer, "is_array": v.is_array,
                 "array_size": v.array_size}
                for v in self.variables
            ],
        }

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    def __repr__(self) -> str:
        return (
            f"CodeContext(file={self.source_file!r}, lang={self.language.value}, "
            f"lines={self.total_lines}, functions={len(self.functions)}, "
            f"call_sites={len(self.call_sites)}, parse_ok={self.parse_success})"
        )