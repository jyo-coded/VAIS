"""
rules/java_rules.py
───────────────────
CWE-mapped vulnerability detection rules for Java programs.

Each rule:
  - Targets specific AST node types
  - Is a pure function (no side effects)
  - Adds VulnObjects to the collection if it fires
  - Never modifies CodeContext

Rules implemented:
  1. SQL injection via string concat in executeQuery/prepareStatement → CWE-89
  2. XXE via DocumentBuilderFactory without disabling external entities → CWE-611
  3. Unsafe deserialization via ObjectInputStream.readObject()         → CWE-502
  4. Path traversal via new File() with user-controlled string         → CWE-22
  5. Command injection via Runtime.getRuntime().exec() with concat     → CWE-78
  6. Hardcoded password in String or char[] assignment                 → CWE-798
  7. Null pointer dereference — return value not checked               → CWE-476
  8. Hardcoded cryptographic key                                       → CWE-321
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


# ─── Rule 1: SQL Injection (CWE-89) ──────────────────────────────────────────

class SqlInjectionRule(BaseRule):
    name       = "sql_injection_string_concat"
    languages  = ["java"]
    node_types = ["method_invocation"]
    description = "SQL query built via string concatenation — SQL injection risk."

    # Matches executeQuery("..." + var) or prepareStatement("..." + var)
    _EXEC_RE = re.compile(
        r'(?:executeQuery|executeUpdate|prepareStatement|createStatement)\s*\('
        r'[^)]*\+',
        re.IGNORECASE
    )

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "method_invocation":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not self._EXEC_RE.search(src_line):
            return

        # Parameterized query with '?' — safe
        if re.search(r'prepareStatement\s*\(\s*"[^"]*\?', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.SQL_INJECTION,
            title="SQL Injection via String Concatenation",
            description=(
                "A SQL query is assembled using string concatenation with a potentially "
                "user-supplied value (CWE-89). An attacker can inject SQL syntax to bypass "
                "authentication, exfiltrate data, or destroy records. "
                "Always use `PreparedStatement` with parameterized placeholders (`?`)."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.CRITICAL, confidence=0.90,
        )


# ─── Rule 2: XXE via DocumentBuilderFactory (CWE-611) ────────────────────────

class XXEDocumentBuilderRule(BaseRule):
    name       = "xxe_document_builder_factory"
    languages  = ["java"]
    node_types = ["method_invocation"]
    description = "DocumentBuilderFactory used without disabling external entity processing."

    def check(self, node, context, collection, source_lines):
        if node.get("type") not in ("method_invocation", "local_variable_declaration",
                                    "variable_declarator"):
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if "DocumentBuilderFactory" not in src_line:
            return

        # Only flag the newInstance() call — this is where the factory is created
        if "newInstance" not in src_line and "DocumentBuilderFactory" not in src_line:
            return

        function = _find_fn(context, line)
        fn_info = context.get_function(function)

        # Check if setFeature disabling external entities appears anywhere in same function
        if fn_info:
            fn_src = source_lines[fn_info.start_line - 1:fn_info.end_line]
            safe_patterns = [
                "setFeature",
                "external-general-entities",
                "external-parameter-entities",
                "disallow-doctype-decl",
                "setExpandEntityReferences",
            ]
            if any(pat in sl for sl in fn_src for pat in safe_patterns):
                return  # Properly mitigated

        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.XXE,
            title="XXE via DocumentBuilderFactory without External Entity Restriction",
            description=(
                "`DocumentBuilderFactory` is used without disabling external entity "
                "processing (CWE-611). An attacker supplying a crafted XML document can "
                "read arbitrary files from the server, perform SSRF, or cause DoS via "
                "entity expansion. Disable external entities with "
                "`factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` and "
                "`factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false)`."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.82,
        )


# ─── Rule 3: Unsafe Deserialization via ObjectInputStream (CWE-502) ──────────

class UnsafeDeserializationRule(BaseRule):
    name       = "unsafe_deserialization_object_input_stream"
    languages  = ["java"]
    node_types = ["method_invocation"]
    description = "ObjectInputStream.readObject() deserializes untrusted data."

    _READ_OBJ = re.compile(r'\.readObject\s*\(\s*\)')

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "method_invocation":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not self._READ_OBJ.search(src_line):
            return

        # Check the broader context for ObjectInputStream
        function = _find_fn(context, line)
        fn_info = context.get_function(function)

        is_ois = False
        if fn_info:
            fn_src = source_lines[fn_info.start_line - 1:fn_info.end_line]
            is_ois = any("ObjectInputStream" in sl for sl in fn_src)
        if not is_ois and "ObjectInputStream" not in src_line:
            return

        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.UNSAFE_DESERIALIZE,
            title="Unsafe Deserialization via ObjectInputStream.readObject()",
            description=(
                "`ObjectInputStream.readObject()` deserializes a byte stream, which triggers "
                "arbitrary class instantiation and method execution (CWE-502). If the stream "
                "originates from an untrusted source, an attacker can craft a gadget chain "
                "to achieve remote code execution. "
                "Use a safe deserialization library (e.g., `SerialKiller`, `Jackson` with "
                "type restrictions) or validate/sign serialized data before deserializing."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.CRITICAL, confidence=0.88,
        )


# ─── Rule 4: Path Traversal via new File() (CWE-22) ──────────────────────────

class PathTraversalNewFileRule(BaseRule):
    name       = "path_traversal_new_file"
    languages  = ["java"]
    node_types = ["object_creation_expression"]
    description = "new File() called with user-controlled string — path traversal risk."

    # new File(userInput) or new File(basePath + userInput)
    _FILE_NEW = re.compile(r'new\s+File\s*\([^)]*(?:\+|userInput|request\.|param|arg)', re.IGNORECASE)

    def check(self, node, context, collection, source_lines):
        if node.get("type") not in ("object_creation_expression", ""):
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not re.search(r'\bnew\s+File\s*\(', src_line):
            return

        # Skip if only a literal path is used
        if re.search(r'new\s+File\s*\(\s*"[^"]*"\s*\)', src_line):
            return

        # Must have a variable or concatenation
        if not re.search(r'new\s+File\s*\([^)]*(?:\+|\w)', src_line):
            return

        # If canonical path validation is nearby — skip
        function = _find_fn(context, line)
        fn_info = context.get_function(function)
        if fn_info:
            fn_src = source_lines[fn_info.start_line - 1:fn_info.end_line]
            if any("getCanonicalPath" in sl or "normalize" in sl or "startsWith" in sl
                   for sl in fn_src):
                return

        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.PATH_TRAVERSAL,
            title="Path Traversal via new File() with User-Controlled Input",
            description=(
                "`new File()` is called with a string that may contain user-supplied data "
                "(CWE-22). An attacker can supply `../` sequences to traverse outside the "
                "intended directory and read/write arbitrary files. "
                "Validate the canonical path: ensure `file.getCanonicalPath().startsWith(baseDir)`."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.78,
        )


# ─── Rule 5: Command Injection via Runtime.exec() (CWE-78) ───────────────────

class RuntimeExecInjectionRule(BaseRule):
    name       = "runtime_exec_command_injection"
    languages  = ["java"]
    node_types = ["method_invocation"]
    description = "Runtime.getRuntime().exec() with string concatenation — command injection."

    _EXEC_RE = re.compile(r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(')

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "method_invocation":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not self._EXEC_RE.search(src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        # Higher severity when concatenation is visible on the same line
        has_concat = "+" in src_line
        severity = Severity.CRITICAL if has_concat else Severity.HIGH

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.COMMAND_INJECTION,
            title="Command Injection via Runtime.getRuntime().exec()",
            description=(
                "`Runtime.getRuntime().exec()` executes OS commands. When the command string "
                "is assembled via concatenation with user-supplied data, an attacker can "
                "inject shell operators (`;`, `&&`, `|`) to run arbitrary commands (CWE-78). "
                "Use `ProcessBuilder` with a string array to separate the command from "
                "arguments, and never pass raw user input."
            ),
            function=function, line=line, snippet=snippet,
            severity=severity, confidence=0.87,
        )


# ─── Rule 6: Hardcoded Password / Credential (CWE-798) ───────────────────────

class HardcodedPasswordRule(BaseRule):
    name       = "hardcoded_password_credential"
    languages  = ["java"]
    node_types = [
        "local_variable_declaration",
        "field_declaration",
        "variable_declarator",
    ]
    description = "Hardcoded password or credential literal detected in source code."

    _SECRET_RE = re.compile(
        r'(?:password|passwd|pwd|secret|credential|apikey|api_key|authtoken|auth_token)'
        r'\s*=\s*["\'][^"\']{4,}["\']',
        re.IGNORECASE,
    )
    _SKIP_RE = re.compile(
        r'(?:your_|example|placeholder|changeme|xxx|todo|<|>|\{|\})',
        re.IGNORECASE,
    )

    def check(self, node, context, collection, source_lines):
        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not self._SECRET_RE.search(src_line):
            return
        if self._SKIP_RE.search(src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.HARDCODED_SECRET,
            title="Hardcoded Password / Credential in Source Code",
            description=(
                "A password or credential is stored as a string literal in source code "
                "(CWE-798). Anyone with access to the repository can extract it. "
                "Load secrets from environment variables (`System.getenv()`) or a "
                "secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager)."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.85,
        )


# ─── Rule 7: Null Pointer Dereference — return not checked (CWE-476) ─────────

class NullReturnNotCheckedRule(BaseRule):
    name       = "null_return_not_checked"
    languages  = ["java"]
    node_types = ["method_invocation"]
    description = "Return value of method that may return null used without null check."

    # Methods known to return null in certain conditions
    _NULLABLE_METHODS = re.compile(
        r'\b(?:get|find|lookup|fetch|load|read|next|peek|poll|remove|getProperty'
        r'|getenv|getParameter|getAttribute|getHeader)\s*\(',
        re.IGNORECASE,
    )

    def check(self, node, context, collection, source_lines):
        if node.get("type") != "method_invocation":
            return

        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        if not self._NULLABLE_METHODS.search(src_line):
            return

        # The result must be immediately chained (dereferenced) on the same line
        # Pattern: something.get(...).method() — no null check
        if not re.search(r'\)\s*\.', src_line):
            return

        # If enclosed in an Optional or null check — skip
        if re.search(r'(?:Optional|Objects\.requireNonNull|!= null|== null|isPresent|orElse)', src_line):
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.NULL_DEREF,
            title="Null Pointer Dereference — Return Value Not Checked",
            description=(
                "The return value of a method that may return `null` is immediately "
                "dereferenced without a null check (CWE-476). If the method returns null, "
                "a `NullPointerException` is thrown at runtime, potentially crashing the "
                "application or exposing stack traces. "
                "Check the return value for null, use `Optional<T>`, or use "
                "`Objects.requireNonNull()`."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.MEDIUM, confidence=0.70,
        )


# ─── Rule 8: Hardcoded Cryptographic Key (CWE-321) ───────────────────────────

class HardcodedCryptoKeyRule(BaseRule):
    name       = "hardcoded_crypto_key"
    languages  = ["java"]
    node_types = [
        "local_variable_declaration",
        "field_declaration",
        "variable_declarator",
        "string_literal",
    ]
    description = "Hardcoded cryptographic key or IV in source code."

    # Variable names suggestive of crypto keys / IVs
    _KEY_VAR_RE = re.compile(
        r'(?:key|secretkey|aeskey|deskey|privatekey|ivspec|initvector|iv|hmackey)'
        r'\s*=\s*',
        re.IGNORECASE,
    )
    # Value is a quoted string literal or byte array literal
    _LITERAL_VAL_RE = re.compile(
        r'(?:["\'][^"\']{4,}["\']|new\s+(?:byte|char)\s*\[\s*\]\s*\{[^}]+\})',
    )
    # SecretKeySpec / IvParameterSpec called with a literal
    _KEY_SPEC_RE = re.compile(
        r'(?:SecretKeySpec|IvParameterSpec|SecretKeyFactory)\s*\(',
    )

    def check(self, node, context, collection, source_lines):
        line = self.node_line(node)
        src_line = self.get_line(source_lines, line)

        matched = False
        if self._KEY_VAR_RE.search(src_line) and self._LITERAL_VAL_RE.search(src_line):
            matched = True
        elif self._KEY_SPEC_RE.search(src_line):
            # Flag if the key is a literal string directly in the call
            if re.search(r'(?:SecretKeySpec|IvParameterSpec)\s*\([^)]*["\']', src_line):
                matched = True
            elif re.search(r'(?:SecretKeySpec|IvParameterSpec)\s*\([^)]*getBytes', src_line):
                # getBytes of a literal is still hardcoded
                matched = True

        if not matched:
            return

        function = _find_fn(context, line)
        snippet = self.get_snippet(source_lines, line, line)

        _make_vuln(
            collection, context,
            rule_name=self.name, cwe=CWE.HARDCODED_CRYPTO_KEY,
            title="Hardcoded Cryptographic Key",
            description=(
                "A cryptographic key or initialization vector is stored as a literal in "
                "source code (CWE-321). Any attacker who can read the source or compiled "
                "bytecode has the key, completely defeating encryption. "
                "Generate keys programmatically (`KeyGenerator.generateKey()`) and store "
                "them in a key management service (KMS) or Java KeyStore."
            ),
            function=function, line=line, snippet=snippet,
            severity=Severity.HIGH, confidence=0.83,
        )


# ─── Rule Registry ────────────────────────────────────────────────────────────

JAVA_RULES: list[BaseRule] = [
    SqlInjectionRule(),
    XXEDocumentBuilderRule(),
    UnsafeDeserializationRule(),
    PathTraversalNewFileRule(),
    RuntimeExecInjectionRule(),
    HardcodedPasswordRule(),
    NullReturnNotCheckedRule(),
    HardcodedCryptoKeyRule(),
]
