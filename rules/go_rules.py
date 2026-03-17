"""
rules/go_rules.py
─────────────────
CWE-mapped vulnerability detection rules for Go programs.

Rules implemented:
  1. exec.Command with user input      → CWE-78
  2. unsafe.Pointer usage              → CWE-242
  3. Ignored error returns (_ =)       → CWE-390
  4. fmt.Sprintf as format string      → CWE-134
  5. os.Args used without validation   → CWE-20
  6. Hardcoded secrets                 → CWE-798
"""

from __future__ import annotations
import re
from typing import TYPE_CHECKING

from rules.base_rule import BaseRule
from rules.vuln_object import VulnObject, VulnCollection, CWE, Severity

if TYPE_CHECKING:
    from core.code_context import CodeContext


def _make_vuln(collection, context, rule_name, cwe, title, description,
               function, line, snippet, severity, confidence):
    vuln_id = collection.generate_id("GO")
    fn_info = context.get_function(function)
    reachable    = context.is_reachable_from_entry(function)
    extern_input = fn_info.extern_input if fn_info else False
    call_depth   = context.function_call_depth(function)
    in_loop      = (fn_info.loop_depth > 0) if fn_info else False

    if reachable and extern_input and severity == Severity.MEDIUM:
        severity = Severity.HIGH

    vuln = VulnObject(
        vuln_id=vuln_id, cwe=cwe, rule_name=rule_name,
        source_file=context.source_file, language="go",
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


# ─── Rule 1: exec.Command Injection ──────────────────────────────────────────

class GoExecCommandRule(BaseRule):
    name       = "go_exec_command_injection"
    languages  = ["go"]
    node_types = ["call_expression"]
    description = "exec.Command with variable arguments enables command injection."

    def check(self, node, context, collection, source_lines):
        for i, src_line in enumerate(source_lines, start=1):
            if not re.search(r'exec\.Command\s*\(', src_line):
                continue

            # Lower risk if all args are string literals
            # Heuristic: if args after first contain variable references
            if re.search(r'exec\.Command\s*\(\s*"[^"]+"\s*\)', src_line):
                continue  # Single literal arg — lower risk

            function = _find_fn(context, i)
            fn_info = context.get_function(function)
            severity = Severity.CRITICAL if (fn_info and fn_info.extern_input) else Severity.HIGH
            snippet = self.get_snippet(source_lines, i, i)

            _make_vuln(
                collection, context,
                rule_name=self.name, cwe=CWE.COMMAND_INJECTION,
                title="Command Injection via exec.Command()",
                description=(
                    "`exec.Command()` is called with variable arguments. If any argument "
                    "derives from user input (os.Args, HTTP request, stdin), an attacker can "
                    "pass malicious values to the executed program (CWE-78). "
                    "Always validate and sanitize all arguments before passing to exec.Command. "
                    "Never pass user input directly as a command name."
                ),
                function=function, line=i, snippet=snippet,
                severity=severity, confidence=0.85,
            )


# ─── Rule 2: unsafe.Pointer Usage ────────────────────────────────────────────

class GoUnsafePointerRule(BaseRule):
    name       = "go_unsafe_pointer"
    languages  = ["go"]
    node_types = ["qualified_type"]
    description = "unsafe.Pointer bypasses Go's memory safety guarantees."

    def check(self, node, context, collection, source_lines):
        for i, src_line in enumerate(source_lines, start=1):
            if "unsafe.Pointer" not in src_line and "unsafe.Sizeof" not in src_line:
                continue

            # Skip import statements
            if "import" in src_line:
                continue

            function = _find_fn(context, i)
            snippet = self.get_snippet(source_lines, i, i)

            _make_vuln(
                collection, context,
                rule_name=self.name, cwe=CWE.UNSAFE_POINTER,
                title="Unsafe Pointer Usage",
                description=(
                    "`unsafe.Pointer` bypasses Go's type system and memory safety guarantees. "
                    "Incorrect usage can cause memory corruption, undefined behavior, and "
                    "potential exploitable vulnerabilities (CWE-242). The `unsafe` package "
                    "should only be used when absolutely necessary and with careful review. "
                    "Audit all arithmetic on `uintptr` values converted from unsafe.Pointer."
                ),
                function=function, line=i, snippet=snippet,
                severity=Severity.MEDIUM, confidence=0.85,
            )


# ─── Rule 3: Ignored Error Returns ───────────────────────────────────────────

class GoIgnoredErrorRule(BaseRule):
    name       = "go_ignored_error"
    languages  = ["go"]
    node_types = ["short_var_declaration"]
    description = "Error return values discarded with blank identifier."

    # Pattern: _, err = ... or result, _ = ...
    BLANK_ASSIGN = re.compile(r'^\s*\w+\s*,\s*_\s*:?=|^\s*_\s*,\s*\w+\s*:?=|^\s*_\s*=')

    def check(self, node, context, collection, source_lines):
        for i, src_line in enumerate(source_lines, start=1):
            if not self.BLANK_ASSIGN.search(src_line):
                continue

            # Skip common safe patterns like range
            if "range " in src_line or "for " in src_line:
                continue

            function = _find_fn(context, i)
            snippet = self.get_snippet(source_lines, i, i)

            _make_vuln(
                collection, context,
                rule_name=self.name, cwe=CWE.UNCHECKED_ERROR,
                title="Ignored Error Return Value",
                description=(
                    "An error return value is discarded using the blank identifier `_`. "
                    "Ignoring errors can mask failures such as failed file operations, "
                    "network errors, or permission denials, leading to silent data corruption "
                    "or security bypasses (CWE-390). "
                    "Always check error return values and handle them explicitly."
                ),
                function=function, line=i, snippet=snippet,
                severity=Severity.MEDIUM, confidence=0.75,
            )


# ─── Rule 4: fmt.Sprintf Format String ───────────────────────────────────────

class GoFmtSprintfRule(BaseRule):
    name       = "go_fmt_sprintf_injection"
    languages  = ["go"]
    node_types = ["call_expression"]
    description = "fmt.Sprintf/Printf with user input as format string."

    FMT_FNS = re.compile(r'fmt\.(Sprintf|Fprintf|Printf|Errorf)\s*\(')

    def check(self, node, context, collection, source_lines):
        for i, src_line in enumerate(source_lines, start=1):
            if not self.FMT_FNS.search(src_line):
                continue

            # Safe: first argument is a string literal
            if re.search(r'fmt\.\w+\s*\(\s*"', src_line):
                continue

            # Also safe: writing to writer as first arg (fmt.Fprintf(w, "..."))
            if re.search(r'fmt\.Fprintf\s*\(\s*\w+\s*,\s*"', src_line):
                continue

            function = _find_fn(context, i)
            snippet = self.get_snippet(source_lines, i, i)

            _make_vuln(
                collection, context,
                rule_name=self.name, cwe=CWE.FORMAT_STRING,
                title="Format String Injection via fmt",
                description=(
                    "A `fmt` formatting function is called with a non-literal format string. "
                    "If this value originates from user input, format verb injection is possible "
                    "(CWE-134). In Go this primarily causes information disclosure via `%v`, "
                    "`%+v` printing internal struct fields. "
                    "Always use a string literal as the format argument: `fmt.Sprintf(\"%s\", val)`."
                ),
                function=function, line=i, snippet=snippet,
                severity=Severity.MEDIUM, confidence=0.72,
            )


# ─── Rule 5: os.Args Without Validation ──────────────────────────────────────

class GoOsArgsRule(BaseRule):
    name       = "go_osargs_no_validation"
    languages  = ["go"]
    node_types = ["selector_expression"]
    description = "os.Args used without bounds checking or input validation."

    def check(self, node, context, collection, source_lines):
        # Look for direct os.Args[n] indexing without length check
        found_args_use = False
        found_len_check = False

        for i, src_line in enumerate(source_lines, start=1):
            if re.search(r'os\.Args\[', src_line):
                found_args_use = True
                args_line = i
            if re.search(r'len\s*\(\s*os\.Args\s*\)', src_line):
                found_len_check = True

        if found_args_use and not found_len_check:
            function = _find_fn(context, args_line)
            snippet = self.get_snippet(source_lines, args_line, args_line)

            _make_vuln(
                collection, context,
                rule_name=self.name, cwe=CWE.UNSAFE_INPUT,
                title="os.Args Accessed Without Length Validation",
                description=(
                    "`os.Args` is indexed directly without first checking `len(os.Args)`. "
                    "If the expected argument is not provided, this causes an index out-of-range "
                    "panic, enabling a denial-of-service condition (CWE-20). "
                    "Always verify `len(os.Args) > n` before accessing `os.Args[n]`."
                ),
                function=function, line=args_line, snippet=snippet,
                severity=Severity.LOW, confidence=0.80,
            )


# ─── Rule 6: Hardcoded Secrets ───────────────────────────────────────────────

class GoHardcodedSecretRule(BaseRule):
    name       = "go_hardcoded_secret"
    languages  = ["go"]
    node_types = ["var_declaration"]
    description = "Hardcoded credentials or secrets in Go source."

    SECRET_PATTERNS = re.compile(
        r'(password|passwd|secret|apiKey|api_key|token|authToken|privateKey'
        r'|accessKey|secretKey|credentials)\s*[=:]\s*"[^"]{4,}"',
        re.IGNORECASE
    )

    def check(self, node, context, collection, source_lines):
        for i, src_line in enumerate(source_lines, start=1):
            if self.SECRET_PATTERNS.search(src_line):
                if any(p in src_line.lower() for p in ["example", "placeholder", "your_", "changeme"]):
                    continue

                function = _find_fn(context, i)
                snippet = self.get_snippet(source_lines, i, i)

                _make_vuln(
                    collection, context,
                    rule_name=self.name, cwe=CWE.HARDCODED_SECRET,
                    title="Hardcoded Secret / Credential",
                    description=(
                        "A hardcoded credential or secret is present in Go source code (CWE-798). "
                        "Secrets in source are exposed to all repository contributors and persist "
                        "in git history. Use `os.Getenv()` or a secrets manager instead."
                    ),
                    function=function, line=i, snippet=snippet,
                    severity=Severity.HIGH, confidence=0.82,
                )


# ─── Rule Registry ────────────────────────────────────────────────────────────

GO_RULES: list[BaseRule] = [
    GoExecCommandRule(),
    GoUnsafePointerRule(),
    GoIgnoredErrorRule(),
    GoFmtSprintfRule(),
    GoOsArgsRule(),
    GoHardcodedSecretRule(),
]