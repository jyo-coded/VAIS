"""
rules/cpp_rules.py
──────────────────
CWE-mapped vulnerability detection rules for C++ programs.

Each rule:
  - Targets specific AST node types
  - Is a pure function (no side effects)
  - Adds VulnObjects to the collection if it fires
  - Never modifies CodeContext

Rules implemented:
  1. Raw new without delete (memory leak)      → CWE-401
  2. Use after delete on raw pointer           → CWE-416
  3. Null pointer dereference (exception path) → CWE-476
  4. char array instead of std::string         → CWE-119
  5. printf with non-literal format string     → CWE-134
  6. system() with string concatenation        → CWE-78
  7. Integer overflow in array size calc       → CWE-190
  8. ofstream without explicit permissions     → CWE-732
"""

from __future__ import annotations
import re
from typing import TYPE_CHECKING

from rules.base_rule import BaseRule
from rules.vuln_object import VulnObject, CWE, Severity

if TYPE_CHECKING:
    from core.code_context import CodeContext


# ─── Shared factory ──────────────────────────────────────────────────────────

def _make_vuln(collection, context, rule_name, cwe, title, description,
               function, line, snippet, severity, confidence):
    vuln_id = collection.generate_id("CPP")
    fn_info = context.get_function(function)
    reachable    = context.is_reachable_from_entry(function)
    extern_input = fn_info.extern_input if fn_info else False
    call_depth   = context.function_call_depth(function)
    in_loop      = (fn_info.loop_depth > 0) if fn_info else False

    if reachable and extern_input and severity == Severity.MEDIUM:
        severity = Severity.HIGH

    vuln = VulnObject(
        vuln_id=vuln_id, cwe=cwe, rule_name=rule_name,
        source_file=context.source_file, language="cpp",
        function_name=function, line_start=line, line_end=line,
        title=title, description=description, code_snippet=snippet,
        severity=severity, confidence=confidence,
        reachable_from_entry=reachable, has_extern_input=extern_input,
        call_depth=call_depth, in_loop=in_loop,
    )
    collection.add(vuln)
    return vuln


def _find_fn(context, line):
    for n, i in context.functions.items():
        if i.start_line <= line <= i.end_line:
            return n
    return "unknown"


# ─── Rule 1: Raw new without delete (CWE-401) ────────────────────────────────

class MemoryLeakNewRule(BaseRule):
    name       = "memory_leak_raw_new"
    languages  = ["cpp"]
    node_types = ["new_expression"]
    description = "Raw `new` allocation without a corresponding `delete` — memory leak."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "new_expression":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        # Skip if new is immediately stored in a smart pointer
        if re.search(r'(?:unique_ptr|shared_ptr|make_unique|make_shared)', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        # Check whether this function has a matching delete via call sites
        has_delete = any(
            cs.callee in ("delete", "delete[]") and cs.caller == function
            for cs in context.call_sites
        )
        # Also scan source lines in the function for `delete`
        if not has_delete:
            fn_info = context.get_function(function)
            if fn_info:
                fn_lines = source_lines[fn_info.start_line - 1:fn_info.end_line]
                has_delete = any("delete" in sl for sl in fn_lines)

        if has_delete:
            return  # delete found — not a clear leak

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.MEMORY_LEAK,
            title="Memory Leak via Raw new without delete",
            description=(
                "A raw `new` expression allocates heap memory but no corresponding `delete` "
                "was found in the same scope (CWE-401). This causes a memory leak. "
                "Prefer `std::unique_ptr<T>` or `std::shared_ptr<T>` for automatic resource management."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.MEDIUM, confidence=0.70,
        )


# ─── Rule 2: Use after delete (CWE-416) ──────────────────────────────────────

class UseAfterDeleteRule(BaseRule):
    name       = "use_after_delete"
    languages  = ["cpp"]
    node_types = ["expression_statement"]
    description = "Pointer used after `delete` — undefined behaviour / exploitable."

    # Regex to find a delete statement and capture the pointer name
    _DELETE_RE = re.compile(r'\bdelete(?:\[\])?\s+(\w+)\s*;')
    # Regex to detect a dereference or member access on a pointer
    _USE_RE    = re.compile(r'\b(\w+)\s*(?:->|\[|\*)')

    def check(self, node, context, collection, source_lines):
        # We operate on each source line inside functions, not the AST node directly
        # (the AST node is used only as a traversal trigger)
        if node.get("type") not in ("expression_statement", ""):
            return

        line = self.node_line(node)
        if line == 0:
            return

        src_line = self.get_line(source_lines, line)
        dm = self._DELETE_RE.search(src_line)
        if not dm:
            return

        deleted_ptr = dm.group(1)
        function = _find_fn(context, line)
        fn_info = context.get_function(function)
        if not fn_info:
            return

        # Scan lines after the delete for any use of the same pointer
        for after_line_idx in range(line, fn_info.end_line):
            after_src = self.get_line(source_lines, after_line_idx + 1)
            # Skip null assignment right after delete — safe pattern
            if re.search(rf'\b{re.escape(deleted_ptr)}\s*=\s*nullptr', after_src):
                break
            um = self._USE_RE.search(after_src)
            if um and um.group(1) == deleted_ptr:
                use_line = after_line_idx + 1
                snippet = self.get_snippet(source_lines, line, use_line)
                _make_vuln(
                    collection, context,
                    rule_name=self.name, cwe=CWE.USE_AFTER_FREE,
                    title="Use After delete on Raw Pointer",
                    description=(
                        f"Pointer `{deleted_ptr}` is deleted at line {line} and then "
                        f"accessed at line {use_line} (CWE-416). Accessing freed memory "
                        "causes undefined behaviour and can be exploited for arbitrary code "
                        "execution. Set the pointer to `nullptr` immediately after `delete`."
                    ),
                    function=function, line=use_line, snippet=snippet,
                    severity=Severity.HIGH, confidence=0.78,
                )
                break


# ─── Rule 3: Null pointer dereference — exception not caught (CWE-476) ───────

class NullPtrExceptionRule(BaseRule):
    name       = "nullptr_dereference_uncaught"
    languages  = ["cpp"]
    node_types = ["pointer_expression"]
    description = "Pointer dereference without null check; exception may propagate uncaught."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "pointer_expression":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        # Only flag if this dereference is NOT inside a null-check condition
        # Heuristic: if a null check (`!= nullptr`, `== nullptr`, `if (ptr)`) appears
        # within 3 lines above, skip.
        for prev in range(max(1, line - 3), line):
            prev_src = self.get_line(source_lines, prev)
            if re.search(r'nullptr|NULL|if\s*\(', prev_src):
                return

        # Skip RAII / smart pointer patterns
        if re.search(r'(?:unique_ptr|shared_ptr|weak_ptr).*\*', src_line):
            return

        # Must be a raw dereference: *ptr or ptr->member
        if not re.search(r'(?:\*\s*\w+|\w+\s*->)', src_line):
            return

        function = _find_fn(context, line)

        # Only report if the containing function has no try-catch block
        fn_info = context.get_function(function)
        if fn_info:
            fn_src = source_lines[fn_info.start_line - 1:fn_info.end_line]
            if any("try" in sl or "catch" in sl for sl in fn_src):
                return  # wrapped in try-catch — lower risk

        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.NULL_DEREF,
            title="Potential Null Pointer Dereference (No Exception Guard)",
            description=(
                "A pointer is dereferenced without a preceding null check and the function "
                "has no try-catch handler (CWE-476). If the pointer is null, the program "
                "will throw `std::bad_alloc` or segfault. Always validate pointers before "
                "dereferencing or use references with RAII smart pointers."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.MEDIUM, confidence=0.65,
        )


# ─── Rule 4: char array instead of std::string (CWE-119) ─────────────────────

class CharArrayInsteadOfStringRule(BaseRule):
    name       = "char_array_buffer_issue"
    languages  = ["cpp"]
    node_types = ["declaration"]
    description = "Fixed-size char array — prefer std::string to avoid buffer issues."

    _CHAR_ARR = re.compile(r'\bchar\s+\w+\s*\[\s*\d+\s*\]')

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "declaration":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not self._CHAR_ARR.search(src_line):
            return

        # Skip purely local constants or format-string literals
        if "const" in src_line and "=" in src_line and '"' in src_line:
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.INTEGER_OVERFLOW,  # CWE-119 — improper restriction
            title="Fixed char Array — Prefer std::string",
            description=(
                "A fixed-size `char` array is declared in a C++ context (CWE-119). "
                "Manual size management is error-prone and can lead to buffer overflow if "
                "input exceeds the declared size. Replace with `std::string` or "
                "`std::array<char, N>` with bounds-checked operations."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.LOW, confidence=0.60,
        )


# ─── Rule 5: printf with non-literal format string (CWE-134) ─────────────────

class CppFormatStringRule(BaseRule):
    name       = "cpp_format_string_injection"
    languages  = ["cpp"]
    node_types = ["call_expression"]
    description = "printf/fprintf called with a non-literal format string."

    FORMAT_FNS = {"printf", "fprintf", "sprintf", "snprintf", "vprintf"}

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        # Must be one of the printf family
        fn_match = re.match(r'\s*(?:\w+\s*=\s*)?(\w+)\s*\(', src_line)
        called = fn_match.group(1) if fn_match else ""
        if called not in self.FORMAT_FNS:
            # Also catch via AST identifier
            fn_node = self.get_child_by_type(node, "identifier")
            called = self.node_text(fn_node) if fn_node else ""
            if called not in self.FORMAT_FNS:
                return

        # If the first argument is a string literal — safe
        if re.search(rf'{re.escape(called)}\s*\(\s*(?:stdout\s*,\s*)?["\']', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.FORMAT_STRING,
            title=f"Format String Injection via {called}()",
            description=(
                f"`{called}()` is called with a non-literal format string (CWE-134). "
                "If the format string is attacker-controlled, format specifiers like `%n` "
                "can be used to read or write arbitrary memory. "
                f"Always use `{called}(\"%s\", variable)` with a hard-coded literal as the format."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.80,
        )


# ─── Rule 6: system() with string concatenation (CWE-78) ─────────────────────

class CppCommandInjectionRule(BaseRule):
    name       = "cpp_system_command_injection"
    languages  = ["cpp"]
    node_types = ["call_expression"]
    description = "system() called with a dynamically constructed string — command injection."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        # Must call system()
        if not re.search(r'\bsystem\s*\(', src_line):
            return

        # Literal-only call — lower risk (but still flag)
        is_literal = bool(re.search(r'system\s*\(\s*["\']', src_line))
        # Concatenation patterns: +, string +, snprintf result, variable
        has_concat = bool(re.search(r'system\s*\(\s*(?:[^"\'(]+\+|cmd|command|buf|input)', src_line))

        if is_literal and not has_concat:
            return  # e.g. system("pause") — skip

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.COMMAND_INJECTION,
            title="Command Injection via system() with String Concatenation",
            description=(
                "`system()` is called with a dynamically constructed command string (CWE-78). "
                "If any portion of the string is derived from user input, shell metacharacters "
                "(`; | && ||`) can be injected to run arbitrary commands. "
                "Use `execve()` with argument arrays instead of `system()`."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.CRITICAL, confidence=0.85,
        )


# ─── Rule 7: Integer overflow in array size calculation (CWE-190) ─────────────

class IntegerOverflowArrayRule(BaseRule):
    name       = "integer_overflow_array_size"
    languages  = ["cpp"]
    node_types = ["new_expression"]
    description = "Array size computed via integer multiplication — potential overflow."

    # Patterns: new T[a * b], new T[count * sizeof(T)], new T[n + m]
    _ARITH = re.compile(r'new\s+\w[\w:<>*\s]*\[\s*\w+\s*[*+]\s*\w+')

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "new_expression":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not self._ARITH.search(src_line):
            return

        # If a cast to size_t or explicit overflow check is present — skip
        if re.search(r'(?:size_t|static_cast|checked_|overflow)', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.INTEGER_OVERFLOW,
            title="Integer Overflow in Array Size Calculation",
            description=(
                "The size expression passed to `new[]` contains an arithmetic operation "
                "on integer values (CWE-190). If the result wraps around (overflows), "
                "a smaller-than-expected buffer is allocated, leading to a heap buffer "
                "overflow when it is filled. Cast values to `size_t` and validate against "
                "maximum bounds before allocation."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.72,
        )


# ─── Rule 8: ofstream without explicit permissions (CWE-732) ─────────────────

class OFStreamPermissionsRule(BaseRule):
    name       = "ofstream_incorrect_permissions"
    languages  = ["cpp"]
    node_types = ["declaration"]
    description = "ofstream file creation without explicit restrictive permissions."

    def check(self, node, context, collection, source_lines):
        if node.get("type") not in ("declaration", "expression_statement"):
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        # Detect ofstream open or construction with a filename
        if not re.search(r'\bofstream\b|\bofs\.open\s*\(|\bfopen\s*\(.*["\']w', src_line):
            return

        # If ios::out | permissions or chmod immediately follows — skip
        if re.search(r'(?:chmod|umask|ios::out\s*\|)', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.INCORRECT_PERMISSIONS,
            title="File Created via ofstream without Explicit Permissions",
            description=(
                "A file is created using `std::ofstream` without explicitly setting "
                "restrictive file permissions (CWE-732). The file will inherit the process "
                "umask, which might allow other users to read sensitive data. "
                "After creation, call `chmod()` with `0600` or set `umask(0077)` "
                "before opening."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.MEDIUM, confidence=0.68,
        )


# ─── Rule Registry ────────────────────────────────────────────────────────────

CPP_RULES: list[BaseRule] = [
    MemoryLeakNewRule(),
    UseAfterDeleteRule(),
    NullPtrExceptionRule(),
    CharArrayInsteadOfStringRule(),
    CppFormatStringRule(),
    CppCommandInjectionRule(),
    IntegerOverflowArrayRule(),
    OFStreamPermissionsRule(),
]
