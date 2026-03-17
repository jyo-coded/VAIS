"""
rules/c_rules.py
────────────────
CWE-mapped vulnerability detection rules for C programs.

Each rule:
  - Targets specific AST node types
  - Is a pure function (no side effects)
  - Adds VulnObjects to the collection if it fires
  - Never modifies CodeContext

Rules implemented:
  1. strcpy / strcat overflow          → CWE-120
  2. gets() usage                      → CWE-120
  3. sprintf without bounds            → CWE-120
  4. scanf with %s (no width limit)    → CWE-120
  5. printf with user input (format)   → CWE-134
  6. system() / popen() injection      → CWE-78
  7. malloc without free (leak)        → CWE-401
  8. use-after-free pattern            → CWE-416
  9. double-free pattern               → CWE-415
 10. memcpy / memmove no bounds        → CWE-125
"""

from __future__ import annotations
from typing import TYPE_CHECKING

from rules.base_rule import BaseRule
from rules.vuln_object import VulnObject, VulnCollection, CWE, Severity

if TYPE_CHECKING:
    from core.code_context import CodeContext


# ─── Helper: build a VulnObject with context enrichment ──────────────────────

def _make_vuln(
    collection:   VulnCollection,
    context:      "CodeContext",
    rule_name:    str,
    cwe:          CWE,
    title:        str,
    description:  str,
    function:     str,
    line:         int,
    snippet:      str,
    severity:     Severity,
    confidence:   float,
) -> VulnObject:
    """
    Factory that builds a VulnObject and enriches it with
    reachability + extern_input data from CodeContext.
    """
    vuln_id = collection.generate_id("C")

    fn_info = context.get_function(function)
    reachable    = context.is_reachable_from_entry(function)
    extern_input = fn_info.extern_input if fn_info else False
    call_depth   = context.function_call_depth(function)
    in_loop      = (fn_info.loop_depth > 0) if fn_info else False

    # Boost severity if reachable from entry AND has external input
    if reachable and extern_input and severity == Severity.MEDIUM:
        severity = Severity.HIGH

    vuln = VulnObject(
        vuln_id=vuln_id,
        cwe=cwe,
        rule_name=rule_name,
        source_file=context.source_file,
        language="c",
        function_name=function,
        line_start=line,
        line_end=line,
        title=title,
        description=description,
        code_snippet=snippet,
        severity=severity,
        confidence=confidence,
        reachable_from_entry=reachable,
        has_extern_input=extern_input,
        call_depth=call_depth,
        in_loop=in_loop,
    )
    collection.add(vuln)
    return vuln


# ─── Rule 1: Unsafe String Copy ──────────────────────────────────────────────

class StrcpyOverflowRule(BaseRule):
    name       = "strcpy_overflow"
    languages  = ["c"]
    node_types = ["call_expression"]
    description = "strcpy/strcat do not perform bounds checking and can overflow destination buffer."

    UNSAFE = {"strcpy", "strcat", "wcscpy", "wcscat"}

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        fn_node = self.get_child_by_type(node, "identifier")
        if not fn_node:
            return

        fn_name = self.node_text(fn_node)
        if fn_name not in self.UNSAFE:
            return

        line = self.node_line(node)
        snippet = self.get_snippet(source_lines, line, line)
        function = self._find_parent_function(context, line)

        _make_vuln(
            collection, context,
            rule_name=self.name,
            cwe=CWE.BUFFER_OVERFLOW,
            title=f"Buffer Overflow via {fn_name}()",
            description=(
                f"`{fn_name}()` copies data into a destination buffer without checking its size. "
                f"If the source string exceeds the destination buffer, memory beyond the buffer "
                f"will be overwritten, potentially allowing arbitrary code execution (CWE-120). "
                f"Replace with `strncpy()` or `strlcpy()` with explicit size limits."
            ),
            function=function,
            line=line,
            snippet=snippet,
            severity=Severity.HIGH,
            confidence=0.90,
        )

    def _find_parent_function(self, context: "CodeContext", line: int) -> str:
        for fn_name, fn_info in context.functions.items():
            if fn_info.start_line <= line <= fn_info.end_line:
                return fn_name
        return "unknown"


# ─── Rule 2: gets() Usage ────────────────────────────────────────────────────

class GetsUsageRule(BaseRule):
    name       = "gets_unbounded_read"
    languages  = ["c"]
    node_types = ["call_expression"]
    description = "gets() reads unlimited input — always a buffer overflow."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        fn_node = self.get_child_by_type(node, "identifier")
        if not fn_node or self.node_text(fn_node) != "gets":
            return

        line = self.node_line(node)
        function = self._find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name,
            cwe=CWE.STACK_OVERFLOW,
            title="Unbounded Input via gets()",
            description=(
                "`gets()` reads from stdin with no length limit and will overflow the destination "
                "buffer if input exceeds its size. This function is so dangerous it was removed "
                "from the C11 standard. Replace with `fgets(buf, sizeof(buf), stdin)`."
            ),
            function=function,
            line=line,
            snippet=snippet,
            severity=Severity.CRITICAL,
            confidence=0.98,
        )

    def _find_fn(self, ctx, line):
        for n, i in ctx.functions.items():
            if i.start_line <= line <= i.end_line:
                return n
        return "unknown"


# ─── Rule 3: sprintf Without Bounds ─────────────────────────────────────────

class SprintfOverflowRule(BaseRule):
    name       = "sprintf_overflow"
    languages  = ["c"]
    node_types = ["call_expression"]
    description = "sprintf writes to a buffer without size limit."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        fn_node = self.get_child_by_type(node, "identifier")
        fn_name = self.node_text(fn_node) if fn_node else ""
        if fn_name != "sprintf":
            return

        line = self.node_line(node)
        function = self._find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name,
            cwe=CWE.BUFFER_OVERFLOW,
            title="Buffer Overflow via sprintf()",
            description=(
                "`sprintf()` writes formatted output into a buffer without checking its size. "
                "A format string that expands larger than the buffer causes overflow. "
                "Replace with `snprintf(buf, sizeof(buf), ...)` to enforce bounds."
            ),
            function=function,
            line=line,
            snippet=snippet,
            severity=Severity.HIGH,
            confidence=0.85,
        )

    def _find_fn(self, ctx, line):
        for n, i in ctx.functions.items():
            if i.start_line <= line <= i.end_line:
                return n
        return "unknown"


# ─── Rule 4: scanf %s Without Width ──────────────────────────────────────────

class ScanfUnboundedRule(BaseRule):
    name       = "scanf_unbounded_string"
    languages  = ["c"]
    node_types = ["call_expression"]
    description = "scanf with %s reads unlimited input into a fixed buffer."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        fn_node = self.get_child_by_type(node, "identifier")
        if not fn_node or self.node_text(fn_node) not in ("scanf", "fscanf", "sscanf"):
            return

        # Check if any string literal argument contains bare %s
        node_str = str(node)
        if '"%s"' not in node_str and "'%s'" not in node_str and "%s" not in node_str:
            return

        line = self.node_line(node)
        function = self._find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        # Check source line directly for bare %s
        src_line = self.get_line(source_lines, line)
        import re
        if not re.search(r'%\d*s', src_line):
            return

        # Bare %s (no width) is the dangerous case
        if re.search(r'%\d+s', src_line):
            return  # Has width specifier — safer

        _make_vuln(
            collection, context,
            rule_name=self.name,
            cwe=CWE.BUFFER_OVERFLOW,
            title="Unbounded scanf %s Read",
            description=(
                "`scanf(\"%s\", ...)` reads a whitespace-delimited string with no length limit. "
                "Input longer than the destination buffer causes overflow. "
                "Use `scanf(\"%Ns\", ...)` where N is buffer_size - 1."
            ),
            function=function,
            line=line,
            snippet=snippet,
            severity=Severity.HIGH,
            confidence=0.80,
        )

    def _find_fn(self, ctx, line):
        for n, i in ctx.functions.items():
            if i.start_line <= line <= i.end_line:
                return n
        return "unknown"


# ─── Rule 5: Format String Bug ───────────────────────────────────────────────

class FormatStringRule(BaseRule):
    name       = "format_string_injection"
    languages  = ["c"]
    node_types = ["call_expression"]
    description = "User-controlled input passed directly as printf format string."

    FORMAT_FNS = {"printf", "fprintf", "sprintf", "snprintf", "vprintf", "syslog"}

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        fn_node = self.get_child_by_type(node, "identifier")
        if not fn_node or self.node_text(fn_node) not in self.FORMAT_FNS:
            return

        fn_name = self.node_text(fn_node)
        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        # Heuristic: if first/only string arg is not a string literal → suspicious
        # printf(user_var) or printf(buf) — no quotes as first argument
        import re
        # Pattern: printf(non_literal) — not printf("...")
        if re.search(rf'{fn_name}\s*\(\s*"', src_line):
            return  # First arg is a string literal — not vulnerable

        function = self._find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name,
            cwe=CWE.FORMAT_STRING,
            title=f"Format String Injection via {fn_name}()",
            description=(
                f"`{fn_name}()` is called with a non-literal first argument. If this value "
                f"originates from user input, an attacker can inject format specifiers (%n, %x) "
                f"to read/write arbitrary memory locations (CWE-134). "
                f"Always use `{fn_name}(\"%s\", user_input)` with a literal format string."
            ),
            function=function,
            line=line,
            snippet=snippet,
            severity=Severity.HIGH,
            confidence=0.80,
        )

    def _find_fn(self, ctx, line):
        for n, i in ctx.functions.items():
            if i.start_line <= line <= i.end_line:
                return n
        return "unknown"


# ─── Rule 6: system() / popen() Injection ────────────────────────────────────

class CommandInjectionRule(BaseRule):
    name       = "command_injection"
    languages  = ["c"]
    node_types = ["call_expression"]
    description = "system()/popen() execute shell commands — dangerous with user input."

    DANGEROUS = {"system", "popen", "execl", "execlp", "execvp"}

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        fn_node = self.get_child_by_type(node, "identifier")
        if not fn_node or self.node_text(fn_node) not in self.DANGEROUS:
            return

        fn_name = self.node_text(fn_node)
        line = self.node_line(node)
        function = self._find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        # Higher severity if function receives external input
        fn_info = context.get_function(function)
        severity = Severity.CRITICAL if (fn_info and fn_info.extern_input) else Severity.HIGH

        _make_vuln(
            collection, context,
            rule_name=self.name,
            cwe=CWE.COMMAND_INJECTION,
            title=f"Command Injection via {fn_name}()",
            description=(
                f"`{fn_name}()` passes a string to the OS shell for execution. If any part of "
                f"this string is user-controlled, an attacker can inject shell metacharacters "
                f"(`;`, `|`, `&&`) to execute arbitrary commands (CWE-78). "
                f"Replace with `execve()` with argument arrays — never pass user input to `{fn_name}()`."
            ),
            function=function,
            line=line,
            snippet=snippet,
            severity=severity,
            confidence=0.88,
        )

    def _find_fn(self, ctx, line):
        for n, i in ctx.functions.items():
            if i.start_line <= line <= i.end_line:
                return n
        return "unknown"


# ─── Rule 7: Use-After-Free ───────────────────────────────────────────────────

class UseAfterFreeRule(BaseRule):
    name       = "use_after_free"
    languages  = ["c"]
    node_types = ["call_expression"]
    description = "Detects usage of a pointer after it has been freed."

    def check(self, node, context, collection, source_lines):
        # Use CodeContext allocation tracking (populated by Phase 1 parser)
        for alloc in context.allocations:
            if alloc.freed and alloc.free_line:
                # Check if the variable is used after the free line
                # Look at call sites in the same function after the free
                for cs in context.call_sites:
                    if (cs.caller == alloc.function
                            and cs.line > alloc.free_line
                            and any(arg_hint in str(cs.args) for arg_hint in ["ptr", "p", "buf", "data", "mem"])):
                        line = cs.line
                        snippet = self.get_snippet(source_lines, alloc.free_line, line)
                        _make_vuln(
                            collection, context,
                            rule_name=self.name,
                            cwe=CWE.USE_AFTER_FREE,
                            title="Potential Use-After-Free",
                            description=(
                                f"Memory allocated at line {alloc.line} is freed at line "
                                f"{alloc.free_line}, but the pointer may be used again at "
                                f"line {line}. Accessing freed memory causes undefined behavior "
                                f"and can be exploited for arbitrary code execution (CWE-416). "
                                f"Set pointer to NULL immediately after free()."
                            ),
                            function=alloc.function,
                            line=line,
                            snippet=snippet,
                            severity=Severity.HIGH,
                            confidence=0.70,
                        )
                        break  # One finding per allocation


# ─── Rule 8: Double-Free ──────────────────────────────────────────────────────

class DoubleFreeRule(BaseRule):
    name       = "double_free"
    languages  = ["c"]
    node_types = ["call_expression"]
    description = "Detects potential double-free of the same pointer."

    def check(self, node, context, collection, source_lines):
        # Track free() calls per function
        free_sites: dict[str, list[int]] = {}

        for cs in context.call_sites:
            if cs.callee == "free" and cs.args:
                arg = cs.args[0].strip("&* ") if cs.args else ""
                key = f"{cs.caller}::{arg}"
                free_sites.setdefault(key, []).append(cs.line)

        for key, lines in free_sites.items():
            if len(lines) >= 2:
                fn_name = key.split("::")[0]
                snippet = self.get_snippet(source_lines, lines[0], lines[-1])
                _make_vuln(
                    collection, context,
                    rule_name=self.name,
                    cwe=CWE.DOUBLE_FREE,
                    title="Double-Free Detected",
                    description=(
                        f"The same pointer appears to be freed more than once "
                        f"(lines {', '.join(map(str, lines))}). Double-free corrupts the heap "
                        f"allocator and can be exploited to gain code execution (CWE-415). "
                        f"Set pointer to NULL after first free to prevent this."
                    ),
                    function=fn_name,
                    line=lines[-1],
                    snippet=snippet,
                    severity=Severity.HIGH,
                    confidence=0.75,
                )


# ─── Rule 9: memcpy / memmove Without Bounds ─────────────────────────────────

class MemcpyBoundsRule(BaseRule):
    name       = "memcpy_no_bounds"
    languages  = ["c"]
    node_types = ["call_expression"]
    description = "memcpy/memmove used with size not derived from destination."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        fn_node = self.get_child_by_type(node, "identifier")
        if not fn_node or self.node_text(fn_node) not in ("memcpy", "memmove", "bcopy"):
            return

        fn_name = self.node_text(fn_node)
        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        # Heuristic: if sizeof(dest) is not in the call — suspicious
        if "sizeof" not in src_line:
            function = self._find_fn(context, line)
            snippet = self.get_snippet(source_lines, line, line)
            _make_vuln(
                collection, context,
                rule_name=self.name,
                cwe=CWE.MISSING_BOUNDS,
                title=f"Possible Out-of-Bounds Write via {fn_name}()",
                description=(
                    f"`{fn_name}()` is called without a size derived from `sizeof(destination)`. "
                    f"If the copy length exceeds the destination buffer, adjacent memory is "
                    f"overwritten (CWE-125). Always use `sizeof(dest)` or `dest_len` as the "
                    f"size argument."
                ),
                function=function,
                line=line,
                snippet=snippet,
                severity=Severity.MEDIUM,
                confidence=0.65,
            )

    def _find_fn(self, ctx, line):
        for n, i in ctx.functions.items():
            if i.start_line <= line <= i.end_line:
                return n
        return "unknown"


# ─── Rule Registry ────────────────────────────────────────────────────────────

C_RULES: list[BaseRule] = [
    StrcpyOverflowRule(),
    GetsUsageRule(),
    SprintfOverflowRule(),
    ScanfUnboundedRule(),
    FormatStringRule(),
    CommandInjectionRule(),
    UseAfterFreeRule(),
    DoubleFreeRule(),
    MemcpyBoundsRule(),
]