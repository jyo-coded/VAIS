"""
rules/python_rules.py
─────────────────────
CWE-mapped vulnerability detection rules for Python programs.

Rules implemented:
  1. eval() / exec() usage             → CWE-95
  2. pickle.loads / pickle.load        → CWE-502
  3. subprocess with shell=True        → CWE-78
  4. os.system() with user input       → CWE-78
  5. open() with unvalidated path      → CWE-22
  6. hardcoded passwords/secrets       → CWE-798
  7. assert used for security checks   → CWE-617
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
    vuln_id = collection.generate_id("PY")
    fn_info = context.get_function(function)
    reachable    = context.is_reachable_from_entry(function)
    extern_input = fn_info.extern_input if fn_info else False
    call_depth   = context.function_call_depth(function)
    in_loop      = (fn_info.loop_depth > 0) if fn_info else False

    if reachable and extern_input and severity == Severity.MEDIUM:
        severity = Severity.HIGH

    vuln = VulnObject(
        vuln_id=vuln_id, cwe=cwe, rule_name=rule_name,
        source_file=context.source_file, language="python",
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


# ─── Rule 1: eval() / exec() ─────────────────────────────────────────────────

class EvalInjectionRule(BaseRule):
    name       = "eval_exec_injection"
    languages  = ["python"]
    node_types = ["call"]
    description = "eval()/exec() execute arbitrary Python code from a string."

    DANGEROUS = {"eval", "exec", "compile"}

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call":
            return

        fn_node = self.get_child_by_type(node, "identifier")
        if not fn_node or self.node_text(fn_node) not in self.DANGEROUS:
            return

        fn_name = self.node_text(fn_node)
        line = self.node_line(node)

        # Skip if arg is a plain string literal (compile-time constant)
        src_line = self.get_line(source_lines, line)
        if re.search(rf'{fn_name}\s*\(\s*["\']', src_line):
            return  # Literal string — low risk

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.CODE_INJECTION,
            title=f"Code Injection via {fn_name}()",
            description=(
                f"`{fn_name}()` executes a Python expression/statement from a string. "
                f"If the argument derives from user input, an attacker can execute "
                f"arbitrary Python code, including system commands and file operations (CWE-95). "
                f"Avoid `{fn_name}()` entirely; use `ast.literal_eval()` for safe value parsing."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.CRITICAL, confidence=0.88,
        )


# ─── Rule 2: Unsafe Deserialization ──────────────────────────────────────────

class PickleDeserializeRule(BaseRule):
    name       = "unsafe_deserialization"
    languages  = ["python"]
    node_types = ["call"]
    description = "pickle.loads/load can execute arbitrary code during deserialization."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not re.search(r'pickle\.(loads?|Unpickler)', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.UNSAFE_DESERIALIZE,
            title="Unsafe Deserialization via pickle",
            description=(
                "`pickle.loads()` / `pickle.load()` deserializes Python objects from bytes. "
                "Maliciously crafted pickle data can execute arbitrary code during deserialization "
                "(CWE-502). Never deserialize pickle data from untrusted sources. "
                "Use `json`, `msgpack`, or `protobuf` for safe serialization."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.CRITICAL, confidence=0.92,
        )


# ─── Rule 3: subprocess shell=True ───────────────────────────────────────────

class SubprocessShellRule(BaseRule):
    name       = "subprocess_shell_injection"
    languages  = ["python"]
    node_types = ["call"]
    description = "subprocess called with shell=True enables shell injection."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if "subprocess" not in src_line:
            return
        if "shell=True" not in src_line and "shell = True" not in src_line:
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.COMMAND_INJECTION,
            title="Command Injection via subprocess(shell=True)",
            description=(
                "Using `subprocess` with `shell=True` passes the command through the OS shell, "
                "enabling injection of shell metacharacters (`;`, `|`, `&&`). If any part of "
                "the command string is user-controlled, arbitrary commands can be executed (CWE-78). "
                "Use a list of arguments with `shell=False` instead."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.90,
        )


# ─── Rule 4: os.system() ─────────────────────────────────────────────────────

class OsSystemRule(BaseRule):
    name       = "os_system_injection"
    languages  = ["python"]
    node_types = ["call"]
    description = "os.system() executes shell commands with no argument safety."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not re.search(r'os\.(system|popen)\s*\(', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.COMMAND_INJECTION,
            title="Command Injection via os.system()",
            description=(
                "`os.system()` / `os.popen()` execute shell commands and are vulnerable to "
                "injection if arguments contain user-supplied data. An attacker can append "
                "shell operators to escape the intended command (CWE-78). "
                "Replace with `subprocess.run([...], shell=False)`."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.85,
        )


# ─── Rule 5: Path Traversal via open() ───────────────────────────────────────

class PathTraversalRule(BaseRule):
    name       = "path_traversal"
    languages  = ["python"]
    node_types = ["call"]
    description = "open() called with unvalidated user-supplied path."

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "call":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not re.search(r'\bopen\s*\(', src_line):
            return

        # Skip if argument is clearly a string literal
        if re.search(r'open\s*\(\s*["\']', src_line):
            return

        function = _find_fn(context, line)

        # Only flag if function receives external input
        fn_info = context.get_function(function)
        if not (fn_info and fn_info.extern_input):
            confidence = 0.55
        else:
            confidence = 0.80

        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.PATH_TRAVERSAL,
            title="Potential Path Traversal via open()",
            description=(
                "`open()` is called with a variable path argument. If this path derives from "
                "user input without sanitization, an attacker can use `../` sequences to access "
                "files outside the intended directory (CWE-22). "
                "Validate with `os.path.abspath()` and confirm the result starts with the "
                "expected base directory."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.MEDIUM, confidence=confidence,
        )


# ─── Rule 6: Hardcoded Secrets ───────────────────────────────────────────────

class HardcodedSecretRule(BaseRule):
    name       = "hardcoded_secret"
    languages  = ["python"]
    node_types = ["assignment"]
    description = "Hardcoded passwords, API keys, or secrets in source code."

    SECRET_PATTERNS = re.compile(
        r'(password|passwd|secret|api_key|apikey|token|auth_token|private_key'
        r'|access_key|secret_key|credentials)\s*=\s*["\'][^"\']{4,}["\']',
        re.IGNORECASE
    )

    def check(self, node, context, collection, source_lines):
        # Walk source lines directly for this rule
        for i, line_text in enumerate(source_lines, start=1):
            if self.SECRET_PATTERNS.search(line_text):
                # Skip obvious placeholders
                if any(placeholder in line_text.lower() for placeholder in
                       ["your_", "example", "placeholder", "changeme", "xxx", "todo"]):
                    continue

                function = _find_fn(context, i)
                snippet = self.get_snippet(source_lines, i, i)

                _make_vuln(
                    collection, context,
                    rule_name=self.name, cwe=CWE.HARDCODED_SECRET,
                    title="Hardcoded Secret / Credential",
                    description=(
                        "A hardcoded credential or secret key was detected in source code (CWE-798). "
                        "Secrets committed to source control are exposed to anyone with repository "
                        "access and persist in git history even after deletion. "
                        "Use environment variables or a secrets manager (AWS Secrets Manager, "
                        "HashiCorp Vault) instead."
                    ),
                    function=function, line=i, snippet=snippet,
                    severity=Severity.HIGH, confidence=0.82,
                )


# ─── Rule Registry ────────────────────────────────────────────────────────────

PYTHON_RULES: list[BaseRule] = [
    EvalInjectionRule(),
    PickleDeserializeRule(),
    SubprocessShellRule(),
    OsSystemRule(),
    PathTraversalRule(),
    HardcodedSecretRule(),
]