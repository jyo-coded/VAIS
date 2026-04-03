"""
rules/java_rules.py
───────────────────
CWE-mapped vulnerability detection rules for Java programs.

Rules implemented:
  1. Runtime.getRuntime().exec()       → CWE-78 (Command Injection)
  2. MessageDigest.getInstance("MD5")  → CWE-327 (Weak Crypto)
  3. Hardcoded passwords/secrets       → CWE-798
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
    vuln_id = collection.generate_id("JAVA")
    fn_info = context.get_function(function)
    reachable    = context.is_reachable_from_entry(function)
    extern_input = fn_info.extern_input if fn_info else False
    call_depth   = context.function_call_depth(function)
    in_loop      = (fn_info.loop_depth > 0) if fn_info else False

    if reachable and extern_input and severity == Severity.MEDIUM:
        severity = Severity.HIGH

    vuln = VulnObject(
        vuln_id=vuln_id, cwe=cwe, rule_name=rule_name,
        source_file=context.source_file, language="java",
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


# ─── Rule 1: Runtime.exec() ──────────────────────────────────────────────────

class RuntimeExecRule(BaseRule):
    name       = "runtime_exec_injection"
    languages  = ["java"]
    node_types = ["method_invocation"]
    description = "Runtime.getRuntime().exec() executes shell commands."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "method_invocation":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not re.search(r'Runtime\.getRuntime\(\)\.exec\s*\(', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.COMMAND_INJECTION,
            title="Command Injection via Runtime.exec()",
            description=(
                "`Runtime.exec()` executes OS commands. If arguments contain user-supplied "
                "data without validation, an attacker can append shell operators to execute "
                "arbitrary commands (CWE-78). ProcessBuilder with rigorous validation should be used."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.85,
        )


# ─── Rule 2: Weak Crypto (MD5 / SHA1) ────────────────────────────────────────

class WeakCryptoRule(BaseRule):
    name       = "weak_crypto_hash"
    languages  = ["java"]
    node_types = ["method_invocation"]
    description = "MessageDigest.getInstance() with MD5 or SHA-1."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "method_invocation":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if "MessageDigest.getInstance" not in src_line:
            return

        match = re.search(r'MessageDigest\.getInstance\(\s*["\'](MD5|SHA-?1)["\']\s*\)', src_line, re.IGNORECASE)
        if not match:
            return

        algo = match.group(1).upper()
        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.WEAK_CRYPTO,
            title=f"Weak Cryptographic Hash ({algo})",
            description=(
                f"Using `{algo}` for cryptographic hashing is weak and susceptible to "
                "collision attacks (CWE-327). Use strong hashing algorithms like SHA-256 "
                "or SHA-3."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.MEDIUM, confidence=0.95,
        )


# ─── Rule 3: Hardcoded Secrets ───────────────────────────────────────────────

class HardcodedSecretRule(BaseRule):
    name       = "hardcoded_secret"
    languages  = ["java"]
    node_types = ["local_variable_declaration", "field_declaration", "assignment"]
    description = "Hardcoded passwords, API keys, or secrets in source code."

    SECRET_PATTERNS = re.compile(
        r'(password|passwd|secret|api[Kk]ey|token|auth[Tt]oken|private[Kk]ey'
        r'|access[Kk]ey|secret[Kk]ey|credentials)\s*=\s*["\'][^"\']{4,}["\']',
        re.IGNORECASE
    )

    def check(self, node, context, collection, source_lines):
        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if self.SECRET_PATTERNS.search(src_line):
            if any(placeholder in src_line.lower() for placeholder in
                   ["your_", "example", "placeholder", "changeme", "xxx", "todo"]):
                return

            function = _find_fn(context, line)
            snippet = self.get_snippet(source_lines, line, line)

            _make_vuln(
                collection, context,
                rule_name=self.name, cwe=CWE.HARDCODED_SECRET,
                title="Hardcoded Secret / Credential",
                description=(
                    "A hardcoded credential or secret key was detected in source code (CWE-798). "
                    "Use environment variables or a secure vault."
                ),
                function=function, line=line, snippet=snippet,
                severity=Severity.HIGH, confidence=0.82,
            )


JAVA_RULES: list[BaseRule] = [
    RuntimeExecRule(),
    WeakCryptoRule(),
    HardcodedSecretRule(),
]
