"""
patch/template_library.py
─────────────────────────
Phase 6: Patch Template Library.

Maps (CWE ID, strategy) → a PatchTemplate that knows how to
transform vulnerable source code into safe source code.

Each template has:
  - match_pattern:   regex to find the vulnerable line(s)
  - apply():         function(source_line, context) -> patched_line(s)
  - description:     human-readable explanation of the fix
  - safe_example:    what the fixed code looks like
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class PatchTemplate:
    """A single patch recipe for one (CWE, strategy) pair."""
    cwe:          str
    strategy:     str
    description:  str
    safe_example: str
    # match_fn: given a source line, returns True if this template applies
    match_fn:     Callable[[str], bool]       = field(repr=False)
    # patch_fn: given (line, function_name, all_lines, line_idx) → list of replacement lines
    patch_fn:     Callable[[str, str, list, int], list[str]] = field(repr=False)


# ─── Helper utilities ────────────────────────────────────────────────────────

def _indent(line: str) -> str:
    """Return the leading whitespace of a line."""
    return line[: len(line) - len(line.lstrip())]


def _strip(line: str) -> str:
    return line.strip()


# ─── CWE-120: Buffer overflow via unsafe string functions ────────────────────

def _patch_strcpy(line: str, fn: str, lines: list, idx: int) -> list[str]:
    ind = _indent(line)
    s   = _strip(line)
    # strcpy(dst, src) → strncpy + null-terminate
    m = re.search(r'strcpy\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)\s*;', s)
    if m:
        dst, src = m.group(1), m.group(2)
        return [
            f"{ind}strncpy({dst}, {src}, sizeof({dst}) - 1);\n",
            f"{ind}{dst}[sizeof({dst}) - 1] = '\\0';  /* bounds-safe copy */\n",
        ]
    return [line]


def _patch_strcat(line: str, fn: str, lines: list, idx: int) -> list[str]:
    ind = _indent(line)
    s   = _strip(line)
    m = re.search(r'strcat\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)\s*;', s)
    if m:
        dst, src = m.group(1), m.group(2)
        return [
            f"{ind}strncat({dst}, {src}, sizeof({dst}) - strlen({dst}) - 1);"
            f"  /* bounds-safe concat */\n",
        ]
    return [line]


def _patch_gets(line: str, fn: str, lines: list, idx: int) -> list[str]:
    ind = _indent(line)
    s   = _strip(line)
    m = re.search(r'gets\s*\(\s*(\w+)\s*\)\s*;', s)
    if m:
        buf = m.group(1)
        return [
            f"{ind}fgets({buf}, sizeof({buf}), stdin);"
            f"  /* replaces unsafe gets() */\n",
            f"{ind}{buf}[strcspn({buf}, \"\\n\")] = 0;"
            f"  /* strip trailing newline */\n",
        ]
    return [line]


def _patch_sprintf(line: str, fn: str, lines: list, idx: int) -> list[str]:
    ind = _indent(line)
    s   = _strip(line)
    m = re.search(r'sprintf\s*\(\s*(\w+)\s*,\s*(.+)\)\s*;', s)
    if m:
        buf  = m.group(1)
        rest = m.group(2)
        return [
            f"{ind}snprintf({buf}, sizeof({buf}), {rest});"
            f"  /* bounds-safe sprintf */\n",
        ]
    return [line]


def _patch_scanf_unbounded(line: str, fn: str, lines: list, idx: int) -> list[str]:
    ind = _indent(line)
    s   = _strip(line)
    # Replace bare %s with %Ns where N=buffer-1
    patched = re.sub(r'"%s"', '"%.255s"', s)
    patched = re.sub(r'%s', '%.255s', patched)
    return [f"{ind}{patched}  /* bounded scanf */\n"]


def _patch_memcpy(line: str, fn: str, lines: list, idx: int) -> list[str]:
    ind = _indent(line)
    s   = _strip(line)
    m = re.search(r'memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(.+?)\s*\)\s*;', s)
    if m:
        dst, src, sz = m.group(1), m.group(2), m.group(3)
        return [
            f"{ind}/* bounds check before memcpy */\n",
            f"{ind}if (({sz}) <= sizeof({dst})) {{\n",
            f"{ind}    memcpy({dst}, {src}, {sz});\n",
            f"{ind}}} else {{\n",
            f"{ind}    memcpy({dst}, {src}, sizeof({dst}));"
            f"  /* clamped to dest size */\n",
            f"{ind}}}\n",
        ]
    return [line]


# ─── Go-specific patches ─────────────────────────────────────────────────────

def _patch_go_exec_command(line: str, fn: str, lines: list, idx: int) -> list[str]:
    """
    Go: Replace exec.Command("bash", "-c", userInput) with direct command execution.
    
    Vulnerable: exec.Command("bash", "-c", input).Run()
    Safe:       exec.Command("bash", input).Run()
    
    This removes the shell interpretation layer and prevents command injection.
    """
    ind = _indent(line)
    s   = _strip(line)
    
    # Match: exec.Command("bash", "-c", arg) or exec.Command("sh", "-c", arg)
    m = re.search(r'exec\.Command\s*\(\s*"(bash|sh)"\s*,\s*"-c"\s*,\s*(.+?)\s*\)', s)
    if m:
        shell = m.group(1)
        arg = m.group(2)
        # Remove the "-c" flag entirely to execute directly
        return [
            f"{ind}// PATCHED: Avoid shell execution (CWE-78)\n",
            f"{ind}exec.Command(\"{shell}\", {arg}).Run()",
        ]
    
    return [line]


# ─── CWE-134: Format string injection ────────────────────────────────────────

def _patch_format_string(line: str, fn: str, lines: list, idx: int) -> list[str]:
    ind = _indent(line)
    s   = _strip(line)
    # printf(var) → printf("%s", var)
    for func in ["printf", "fprintf", "sprintf", "snprintf"]:
        pattern = rf'{func}\s*\(([^"\')\s][^)]*)\)\s*;'
        m = re.search(pattern, s)
        if m:
            args = m.group(1).strip()
            # If first arg looks like a variable (not a string literal)
            if not args.startswith('"'):
                return [
                    f'{ind}{func}("%s", {args});'
                    f'  /* literal format string */\n',
                ]
    return [line]


# ─── CWE-78: Command injection ───────────────────────────────────────────────

def _patch_system_call(line: str, fn: str, lines: list, idx: int) -> list[str]:
    ind = _indent(line)
    s   = _strip(line)
    m = re.search(r'system\s*\(\s*(.+?)\s*\)\s*;', s)
    if m:
        arg = m.group(1)
        return [
            f"{ind}/* PATCHED: replaced system() with execve - no shell injection */\n",
            f"{ind}{{\n",
            f"{ind}    char *argv[] = {{\"sh\", \"-c\", {arg}, NULL}};\n",
            f"{ind}    /* TODO: replace with direct execve call without shell */\n",
            f"{ind}    /* execve(\"/bin/sh\", argv, NULL); */\n",
            f"{ind}    (void)argv;  /* remove this line when implementing execve */\n",
            f"{ind}}}\n",
        ]
    return [line]


# ─── CWE-416: Use after free ─────────────────────────────────────────────────

def _patch_use_after_free(line: str, fn: str, lines: list, idx: int) -> list[str]:
    ind = _indent(line)
    s   = _strip(line)
    m = re.search(r'free\s*\(\s*(\w+)\s*\)\s*;', s)
    if m:
        ptr = m.group(1)
        return [
            f"{ind}free({ptr});\n",
            f"{ind}{ptr} = NULL;  /* prevent use-after-free */\n",
        ]
    return [line]


# ─── CWE-415: Double free ────────────────────────────────────────────────────

def _patch_double_free(line: str, fn: str, lines: list, idx: int) -> list[str]:
    ind = _indent(line)
    s   = _strip(line)
    m = re.search(r'free\s*\(\s*(\w+)\s*\)\s*;', s)
    if m:
        ptr = m.group(1)
        return [
            f"{ind}if ({ptr} != NULL) {{\n",
            f"{ind}    free({ptr});\n",
            f"{ind}    {ptr} = NULL;  /* prevent double-free */\n",
            f"{ind}}}\n",
        ]
    return [line]


# ─── Template registry ────────────────────────────────────────────────────────

TEMPLATES: list[PatchTemplate] = [

    PatchTemplate(
        cwe="CWE-120", strategy="replace_strcpy_with_strncpy",
        description="Replace strcpy with strncpy + explicit null-terminator",
        safe_example='strncpy(dst, src, sizeof(dst) - 1); dst[sizeof(dst)-1] = \'\\0\';',
        match_fn=lambda l: bool(re.search(r'\bstrcpy\s*\(', l)),
        patch_fn=_patch_strcpy,
    ),

    PatchTemplate(
        cwe="CWE-120", strategy="replace_strcat_with_strncat",
        description="Replace strcat with strncat with size limit",
        safe_example='strncat(dst, src, sizeof(dst) - strlen(dst) - 1);',
        match_fn=lambda l: bool(re.search(r'\bstrcat\s*\(', l)),
        patch_fn=_patch_strcat,
    ),

    PatchTemplate(
        cwe="CWE-120", strategy="replace_gets_with_fgets",
        description="Replace gets() with fgets() + newline strip",
        safe_example='fgets(buf, sizeof(buf), stdin); buf[strcspn(buf,"\\n")] = 0;',
        match_fn=lambda l: bool(re.search(r'\bgets\s*\(', l)),
        patch_fn=_patch_gets,
    ),

    PatchTemplate(
        cwe="CWE-120", strategy="replace_with_safe_alternative",
        description="Replace unsafe input function with safe bounded alternative",
        safe_example='fgets(buf, sizeof(buf), stdin); buf[strcspn(buf,"\\n")] = 0;',
        match_fn=lambda l: bool(re.search(r'\bgets\s*\(', l)),
        patch_fn=_patch_gets,
    ),

    PatchTemplate(
        cwe="CWE-120", strategy="replace_sprintf_with_snprintf",
        description="Replace sprintf with snprintf to enforce buffer limit",
        safe_example='snprintf(buf, sizeof(buf), fmt, args);',
        match_fn=lambda l: bool(re.search(r'\bsprintf\s*\(', l)),
        patch_fn=_patch_sprintf,
    ),

    PatchTemplate(
        cwe="CWE-120", strategy="add_bounds_check",
        description="Add explicit bounds check before copy",
        safe_example='if (len < sizeof(dst)) { memcpy(dst, src, len); }',
        match_fn=lambda l: bool(re.search(r'\bscanf\s*\(', l)),
        patch_fn=_patch_scanf_unbounded,
    ),

    PatchTemplate(
        cwe="CWE-125", strategy="validate_copy_length",
        description="Add bounds check before memcpy",
        safe_example='if (n <= sizeof(dst)) { memcpy(dst, src, n); }',
        match_fn=lambda l: bool(re.search(r'\bmemcpy\s*\(', l)),
        patch_fn=_patch_memcpy,
    ),

    PatchTemplate(
        cwe="CWE-134", strategy="add_literal_format_string",
        description="Add literal format string to printf-family calls",
        safe_example='printf("%s", user_input);',
        match_fn=lambda l: bool(re.search(
            r'\b(printf|fprintf|sprintf|snprintf)\s*\([^"\')\s]', l
        )),
        patch_fn=_patch_format_string,
    ),

    PatchTemplate(
        cwe="CWE-78", strategy="use_execve_arg_array",
        description="Replace system() shell call with execve arg array",
        safe_example='char *argv[] = {"/bin/ls", arg, NULL}; execve(argv[0], argv, NULL);',
        match_fn=lambda l: bool(re.search(r'\bsystem\s*\(', l)),
        patch_fn=_patch_system_call,
    ),

    PatchTemplate(
        cwe="CWE-78", strategy="use_arg_list_no_shell",
        description="Replace shell-based execution with direct arg list",
        safe_example='char *argv[] = {"/bin/ls", arg, NULL}; execve(argv[0], argv, NULL);',
        match_fn=lambda l: bool(re.search(r'\bsystem\s*\(', l)),
        patch_fn=_patch_system_call,
    ),

    PatchTemplate(
        cwe="CWE-416", strategy="set_pointer_null_after_free",
        description="Set pointer to NULL immediately after free()",
        safe_example='free(ptr); ptr = NULL;',
        match_fn=lambda l: bool(re.search(r'\bfree\s*\(', l)),
        patch_fn=_patch_use_after_free,
    ),

    PatchTemplate(
        cwe="CWE-415", strategy="add_null_check_before_free",
        description="Guard free() with NULL check and zero pointer after",
        safe_example='if (ptr != NULL) { free(ptr); ptr = NULL; }',
        match_fn=lambda l: bool(re.search(r'\bfree\s*\(', l)),
        patch_fn=_patch_double_free,
    ),

    # ─── Go patches for CWE-78: Command Injection ─────────────────────────
    PatchTemplate(
        cwe="CWE-78", strategy="use_arg_list_no_shell",
        description="Go: Remove -c flag from exec.Command() to prevent shell injection",
        safe_example='exec.Command("bash", arg).Run()  // Direct execution without shell',
        match_fn=lambda l: bool(re.search(r'exec\.Command\s*\(\s*"(bash|sh)"\s*,\s*"-c"', l)),
        patch_fn=_patch_go_exec_command,
    ),

    PatchTemplate(
        cwe="CWE-78", strategy="sanitize_input",
        description="Go: Remove -c flag from exec.Command() to prevent shell injection",
        safe_example='exec.Command("bash", arg).Run()  // Direct execution without shell',
        match_fn=lambda l: bool(re.search(r'exec\.Command\s*\(\s*"(bash|sh)"\s*,\s*"-c"', l)),
        patch_fn=_patch_go_exec_command,
    ),
]

# ─── Lookup ───────────────────────────────────────────────────────────────────

def get_template(
    cwe:      str,
    strategy: str,
    target_line: Optional[str] = None,
) -> Optional[PatchTemplate]:
    """
    Return the best matching template for a (CWE, strategy) pair.
    
    If target_line is provided, it will test match_fn on it and prefer
    templates that actually match the line content.
    """
    candidates = []
    
    # Exact match (CWE + strategy)
    for t in TEMPLATES:
        if t.cwe == cwe and t.strategy == strategy:
            candidates.append(t)
    
    if candidates:
        # If we have the target line, find one that matches
        if target_line:
            for t in candidates:
                if t.match_fn(target_line):
                    return t
        # Otherwise return first candidate
        return candidates[0] if candidates else None

    # Strategy match only (CWE may vary due to overlapping strategies)
    candidates = []
    for t in TEMPLATES:
        if t.strategy == strategy:
            candidates.append(t)
    
    if candidates:
        # If we have the target line, find one that matches
        if target_line:
            for t in candidates:
                if t.match_fn(target_line):
                    return t
        # Otherwise return first candidate
        return candidates[0] if candidates else None

    # CWE match only — return first template for this CWE
    for t in TEMPLATES:
        if t.cwe == cwe:
            return t

    return None


def get_templates_for_cwe(cwe: str) -> list[PatchTemplate]:
    """Return all templates for a given CWE."""
    return [t for t in TEMPLATES if t.cwe == cwe]