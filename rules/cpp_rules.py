"""
rules/cpp_rules.py
──────────────────
CWE-mapped vulnerability detection rules for C++ programs.

Rules implemented:
  1. std::strcpy / strcpy              → CWE-120
  2. std::system / system              → CWE-78
  3. std::gets / gets                  → CWE-242
"""

from __future__ import annotations
import re
from typing import TYPE_CHECKING

from rules.base_rule import BaseRule
from rules.vuln_object import VulnObject, CWE, Severity

if TYPE_CHECKING:
    from core.code_context import CodeContext


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


# ─── Rule 1: strcpy() / std::strcpy() ────────────────────────────────────────

class StrcpyRule(BaseRule):
    name       = "strcpy_buffer_copy"
    languages  = ["cpp"]
    node_types = ["call_expression"]
    description = "strcpy() copies strings without bounds checking."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not re.search(r'\b(?:std::)?strcpy\s*\(', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.BUFFER_COPY_WITHOUT_CHECKING_SIZE,
            title="Unchecked Buffer Copy via strcpy()",
            description=(
                "`strcpy()` does not bounds-check the destination buffer, which can lead to "
                "buffer overflows (CWE-120). Use `std::strncpy()` or `std::string` instead."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.88,
        )


# ─── Rule 2: system() / std::system() ────────────────────────────────────────

class SystemRule(BaseRule):
    name       = "system_command_injection"
    languages  = ["cpp"]
    node_types = ["call_expression"]
    description = "system() runs shell commands, potentially leading to injection."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not re.search(r'\b(?:std::)?system\s*\(', src_line):
            return

        # literal string like std::system("pause") is lower risk
        if re.search(r'(?:std::)?system\s*\(\s*["\']', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.COMMAND_INJECTION,
            title="Command Injection via system()",
            description=(
                "`system()` executes shell commands. If arguments contain user-supplied "
                "data without validation, an attacker can execute arbitrary commands (CWE-78)."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.85,
        )


# ─── Rule 3: gets() / std::gets() ────────────────────────────────────────

class GetsRule(BaseRule):
    name       = "gets_buffer_overflow"
    languages  = ["cpp"]
    node_types = ["call_expression"]
    description = "gets() is inherently unsafe and leads to buffer overflows."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call_expression":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not re.search(r'\b(?:std::)?gets\s*\(', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.USE_OF_INHERENTLY_DANGEROUS_FUNCTION,
            title="Dangerous Function: gets()",
            description=(
                "`gets()` reads from stdin into a buffer without performing bounds checking. "
                "It is impossible to use `gets()` securely (CWE-242). Use `std::fgets()` or "
                "`std::cin`."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.CRITICAL, confidence=0.98,
        )


CPP_RULES: list[BaseRule] = [
    StrcpyRule(),
    SystemRule(),
    GetsRule(),
]
