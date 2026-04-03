"""
core/parser.py
──────────────
Phase 1, Step 1: Language-aware AST parser.
Converts source files → CodeContext objects using Tree-sitter.

Each language has its own _parse_<lang> method.
All methods populate the SAME CodeContext schema — downstream phases
never need to know which language was parsed.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Optional

from core.code_context import (
    CodeContext, Language, FunctionInfo,
    AllocationSite, VariableScope, CallSite,
)

# ── Tree-sitter imports (graceful degradation if not installed) ────────────
try:
    import tree_sitter_c as tsc
    import tree_sitter_python as tspy
    import tree_sitter_go as tsgo
    import tree_sitter_java as tsjava
    import tree_sitter_cpp as tscpp
    from tree_sitter import Language as TSLanguage, Parser as TSParser, Node
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False


# ─── Language-specific constants ────────────────────────────────────────────

# C: unsafe functions the rule engine cares about (also used in feature extraction)
C_UNSAFE_ALLOC   = {"malloc", "calloc", "realloc"}
C_FREE_CALLS     = {"free"}
C_UNSAFE_FUNCS   = {
    "strcpy", "strcat", "sprintf", "gets", "scanf",
    "printf", "fprintf", "system", "popen", "exec",
    "memcpy", "memmove", "strncpy",
}
C_ENTRY_POINTS   = {"main"}

# Python: dangerous builtins / sinks
PY_UNSAFE_FUNCS  = {
    "eval", "exec", "compile", "pickle.loads", "pickle.load",
    "subprocess.call", "subprocess.Popen", "os.system",
    "os.popen", "open", "input",
}
PY_ENTRY_MARKERS = {"main", "__main__"}

# Go: risky patterns
GO_UNSAFE_FUNCS  = {
    "os.Exec", "exec.Command", "unsafe.Pointer",
    "fmt.Sprintf", "fmt.Fprintf",
}
GO_ALLOC_FUNCS   = {"make", "new"}
GO_ENTRY_POINTS  = {"main", "init"}

# Java: dangerous builtins / sinks
JAVA_UNSAFE_FUNCS = {
    "Runtime.getRuntime().exec", "ProcessBuilder", "MessageDigest.getInstance",
    "System.loadLibrary", "ObjectInputStream.readObject",
}
JAVA_ENTRY_POINTS = {"main"}

# C++: risky patterns
CPP_UNSAFE_FUNCS = {
    "std::strcpy", "std::system", "std::sprintf", "std::gets",
    "std::memcpy", "system", "strcpy", "sprintf", "gets", "memcpy",
}
CPP_ALLOC_FUNCS  = {"new", "new[]", "malloc", "calloc"}
CPP_FREE_CALLS   = {"delete", "delete[]", "free"}
CPP_ENTRY_POINTS = {"main"}


# ─── Parser ─────────────────────────────────────────────────────────────────

class ASTParser:
    """
    Wraps Tree-sitter to parse source files into CodeContext objects.

    Usage:
        parser = ASTParser()
        ctx = parser.parse("main.c", Language.C)
    """

    def __init__(self):
        if not _TS_AVAILABLE:
            raise RuntimeError(
                "Tree-sitter not installed. Run: pip install -r requirements.txt"
            )
        # Build language objects — handle both v0.21.x and v0.22+ APIs
        try:
            # v0.21.x: Language(ptr, name)
            self._ts_c      = TSLanguage(tsc.language(), "c")
            self._ts_python = TSLanguage(tspy.language(), "python")
            self._ts_go     = TSLanguage(tsgo.language(), "go")
            self._ts_java   = TSLanguage(tsjava.language(), "java")
            self._ts_cpp    = TSLanguage(tscpp.language(), "cpp")
        except TypeError:
            # v0.22+: Language(ptr) only
            self._ts_c      = TSLanguage(tsc.language())
            self._ts_python = TSLanguage(tspy.language())
            self._ts_go     = TSLanguage(tsgo.language())
            self._ts_java   = TSLanguage(tsjava.language())
            self._ts_cpp    = TSLanguage(tscpp.language())

    # ── Public entry point ────────────────────────────────────────────────

    def parse(self, file_path: str | Path, language: Language) -> CodeContext:
        """
        Parse a source file and return a fully populated CodeContext.
        This is the only method downstream phases should call.
        """
        file_path = Path(file_path)
        source = file_path.read_text(encoding="utf-8", errors="replace")
        lines  = source.splitlines()

        ctx = CodeContext(
            source_file=str(file_path),
            language=language,
            total_lines=len(lines),
        )

        dispatch = {
            Language.C:      (self._ts_c,      self._parse_c),
            Language.PYTHON: (self._ts_python,  self._parse_python),
            Language.GO:     (self._ts_go,      self._parse_go),
            Language.JAVA:   (self._ts_java,    self._parse_java),
            Language.CPP:    (self._ts_cpp,     self._parse_cpp),
        }

        ts_lang, parse_fn = dispatch[language]

        # Handle both v0.21.x (set_language method) and v0.25+ (language property) APIs
        parser = TSParser()
        try:
            # Try v0.21.x: set_language() method
            parser.set_language(ts_lang)
        except AttributeError:
            # v0.25+: use language property
            parser.language = ts_lang

        try:
            tree = parser.parse(source.encode("utf-8"))
            # Partial parse is still useful — don't abort on error nodes
            if tree.root_node.has_error:
                ctx.parse_errors.append("AST contains error nodes (partial parse)")
            ctx.ast_json = self._node_to_dict(tree.root_node, source)
            parse_fn(tree.root_node, source, lines, ctx)
        except Exception as e:
            ctx.parse_success = False
            ctx.parse_errors.append(f"Parse error: {e}")

        # Mark entry points on function infos
        for ep in ctx.entry_points:
            if ep in ctx.functions:
                ctx.functions[ep].is_entry = True

        return ctx

    # ── C Parser ──────────────────────────────────────────────────────────

    def _parse_c(self, root: "Node", source: str, lines: list[str], ctx: CodeContext) -> None:
        """Walk C AST and populate CodeContext."""
        src_bytes = source.encode("utf-8")

        def walk(node: "Node", current_fn: Optional[str] = None):
            # ── Function definition ──────────────────────────────────────
            if node.type == "function_definition":
                fn_name = self._c_function_name(node, src_bytes)
                if fn_name:
                    fn_info = FunctionInfo(
                        name=fn_name,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        params=self._c_params(node, src_bytes),
                        return_type=self._c_return_type(node, src_bytes),
                        is_entry=fn_name in C_ENTRY_POINTS,
                        loop_depth=self._max_loop_depth(node),
                        extern_input=self._c_has_extern_input(node, src_bytes),
                    )
                    ctx.functions[fn_name] = fn_info
                    if fn_name in C_ENTRY_POINTS:
                        ctx.entry_points.append(fn_name)
                    current_fn = fn_name

            # ── Call expression ──────────────────────────────────────────
            elif node.type == "call_expression":
                callee = self._node_text(node.child_by_field_name("function"), src_bytes)
                if callee and current_fn:
                    line = node.start_point[0] + 1
                    args = self._c_call_args(node, src_bytes)
                    ctx.call_sites.append(CallSite(
                        caller=current_fn, callee=callee, line=line, args=args
                    ))
                    if current_fn in ctx.functions:
                        if callee not in ctx.functions[current_fn].calls:
                            ctx.functions[current_fn].calls.append(callee)

                    # Track allocations
                    if callee in C_UNSAFE_ALLOC:
                        ctx.allocations.append(AllocationSite(
                            function=current_fn, line=line, alloc_type=callee
                        ))

                    # Mark corresponding frees (simple heuristic)
                    if callee in C_FREE_CALLS and args:
                        freed_var = args[0].strip("&* ")
                        for alloc in ctx.allocations:
                            if alloc.function == current_fn and not alloc.freed:
                                alloc.freed = True
                                alloc.free_line = line
                                break

            # ── Variable declaration ─────────────────────────────────────
            elif node.type == "declaration" and current_fn:
                self._c_extract_variables(node, src_bytes, current_fn, ctx)

            # ── Pointer arithmetic ───────────────────────────────────────
            elif node.type in ("pointer_expression", "subscript_expression"):
                if current_fn and current_fn in ctx.functions:
                    ctx.functions[current_fn].pointer_ops += 1

            for child in node.children:
                walk(child, current_fn)

        walk(root)

    def _c_function_name(self, node: "Node", src: bytes) -> Optional[str]:
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            return None
        # Handle: int func(...) and int *func(...)
        if declarator.type == "function_declarator":
            name_node = declarator.child_by_field_name("declarator")
            return self._node_text(name_node, src)
        if declarator.type == "pointer_declarator":
            inner = declarator.child_by_field_name("declarator")
            if inner and inner.type == "function_declarator":
                name_node = inner.child_by_field_name("declarator")
                return self._node_text(name_node, src)
        return self._node_text(declarator, src)

    def _c_params(self, fn_node: "Node", src: bytes) -> list[str]:
        params = []
        declarator = fn_node.child_by_field_name("declarator")
        if declarator:
            for child in declarator.children:
                if child.type == "parameter_list":
                    for param in child.children:
                        if param.type == "parameter_declaration":
                            params.append(self._node_text(param, src))
        return params

    def _c_return_type(self, fn_node: "Node", src: bytes) -> Optional[str]:
        type_node = fn_node.child_by_field_name("type")
        return self._node_text(type_node, src) if type_node else None

    def _c_call_args(self, call_node: "Node", src: bytes) -> list[str]:
        args_node = call_node.child_by_field_name("arguments")
        if not args_node:
            return []
        return [
            self._node_text(child, src)
            for child in args_node.children
            if child.type not in ("(", ")", ",")
        ]

    def _c_extract_variables(self, decl_node: "Node", src: bytes, fn: str, ctx: CodeContext) -> None:
        type_text = ""
        type_node = decl_node.child_by_field_name("type")
        if type_node:
            type_text = self._node_text(type_node, src) or ""

        for child in decl_node.children:
            if child.type in ("init_declarator", "identifier", "pointer_declarator", "array_declarator"):
                name = self._node_text(child, src)
                if name:
                    is_ptr   = "*" in name or type_text.count("*") > 0
                    is_arr   = "[" in name
                    arr_size = None
                    if is_arr:
                        m = re.search(r'\[(\d+)\]', name)
                        arr_size = int(m.group(1)) if m else None
                    ctx.variables.append(VariableScope(
                        name=name.strip("* "),
                        var_type=type_text,
                        function=fn,
                        declared_line=decl_node.start_point[0] + 1,
                        is_pointer=is_ptr,
                        is_array=is_arr,
                        array_size=arr_size,
                    ))

    def _c_has_extern_input(self, fn_node: "Node", src: bytes) -> bool:
        """Heuristic: function reads from external input if it calls scanf/gets/fgets/argv."""
        text = self._node_text(fn_node, src) or ""
        return any(kw in text for kw in ("scanf", "gets", "fgets", "argv", "stdin", "read(", "recv("))

    # ── Python Parser ─────────────────────────────────────────────────────

    def _parse_python(self, root: "Node", source: str, lines: list[str], ctx: CodeContext) -> None:
        src_bytes = source.encode("utf-8")

        def walk(node: "Node", current_fn: Optional[str] = None, depth: int = 0):
            # ── Function/method definition ───────────────────────────────
            if node.type in ("function_definition", "decorated_definition"):
                target = node
                if node.type == "decorated_definition":
                    for child in node.children:
                        if child.type == "function_definition":
                            target = child
                            break

                name_node = target.child_by_field_name("name")
                fn_name = self._node_text(name_node, src_bytes)
                if fn_name:
                    params = self._py_params(target, src_bytes)
                    fn_info = FunctionInfo(
                        name=fn_name,
                        start_line=target.start_point[0] + 1,
                        end_line=target.end_point[0] + 1,
                        params=params,
                        loop_depth=self._max_loop_depth(target),
                        extern_input=self._py_has_extern_input(target, src_bytes),
                    )
                    ctx.functions[fn_name] = fn_info
                    if fn_name == "main" or depth == 0:
                        ctx.entry_points.append(fn_name)
                    current_fn = fn_name

            # ── Call expression ──────────────────────────────────────────
            elif node.type == "call":
                callee_node = node.child_by_field_name("function")
                callee = self._node_text(callee_node, src_bytes)
                if callee and current_fn:
                    line = node.start_point[0] + 1
                    ctx.call_sites.append(CallSite(
                        caller=current_fn, callee=callee, line=line
                    ))
                    if current_fn in ctx.functions:
                        if callee not in ctx.functions[current_fn].calls:
                            ctx.functions[current_fn].calls.append(callee)

            # ── Variable assignment (simple tracking) ────────────────────
            elif node.type == "assignment" and current_fn:
                left = node.child_by_field_name("left")
                var_name = self._node_text(left, src_bytes)
                if var_name:
                    ctx.variables.append(VariableScope(
                        name=var_name,
                        var_type="dynamic",
                        function=current_fn,
                        declared_line=node.start_point[0] + 1,
                    ))

            for child in node.children:
                walk(child, current_fn, depth)

        walk(root)

        # Python: if __name__ == "__main__" block → mark as entry
        if "__main__" not in ctx.entry_points:
            if "__name__" in source and "__main__" in source:
                ctx.entry_points.append("__main__")

    def _py_params(self, fn_node: "Node", src: bytes) -> list[str]:
        params_node = fn_node.child_by_field_name("parameters")
        if not params_node:
            return []
        return [
            self._node_text(child, src)
            for child in params_node.children
            if child.type not in ("(", ")", ",")
        ]

    def _py_has_extern_input(self, fn_node: "Node", src: bytes) -> bool:
        text = self._node_text(fn_node, src) or ""
        return any(kw in text for kw in ("input(", "sys.stdin", "open(", "request", "argv"))

    # ── Go Parser ─────────────────────────────────────────────────────────

    def _parse_go(self, root: "Node", source: str, lines: list[str], ctx: CodeContext) -> None:
        src_bytes = source.encode("utf-8")

        def walk(node: "Node", current_fn: Optional[str] = None):
            # ── Function declaration ─────────────────────────────────────
            if node.type == "function_declaration":
                name_node = node.child_by_field_name("name")
                fn_name = self._node_text(name_node, src_bytes)
                if fn_name:
                    fn_info = FunctionInfo(
                        name=fn_name,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        params=self._go_params(node, src_bytes),
                        loop_depth=self._max_loop_depth(node),
                        is_entry=fn_name in GO_ENTRY_POINTS,
                        extern_input=self._go_has_extern_input(node, src_bytes),
                    )
                    ctx.functions[fn_name] = fn_info
                    if fn_name in GO_ENTRY_POINTS:
                        ctx.entry_points.append(fn_name)
                    current_fn = fn_name

            # ── Method declaration ───────────────────────────────────────
            elif node.type == "method_declaration":
                name_node = node.child_by_field_name("name")
                fn_name = self._node_text(name_node, src_bytes)
                if fn_name and fn_name not in ctx.functions:
                    fn_info = FunctionInfo(
                        name=fn_name,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        loop_depth=self._max_loop_depth(node),
                        extern_input=self._go_has_extern_input(node, src_bytes),
                    )
                    ctx.functions[fn_name] = fn_info
                    current_fn = fn_name

            # ── Call expressions ─────────────────────────────────────────
            elif node.type == "call_expression":
                fn_field = node.child_by_field_name("function")
                callee = self._node_text(fn_field, src_bytes)
                if callee and current_fn:
                    line = node.start_point[0] + 1
                    ctx.call_sites.append(CallSite(
                        caller=current_fn, callee=callee, line=line
                    ))
                    if current_fn in ctx.functions:
                        if callee not in ctx.functions[current_fn].calls:
                            ctx.functions[current_fn].calls.append(callee)

                    # Track make/new allocations
                    if callee in GO_ALLOC_FUNCS:
                        ctx.allocations.append(AllocationSite(
                            function=current_fn, line=line, alloc_type=callee, freed=True  # GC managed
                        ))

            # ── Short variable declaration (:=) ─────────────────────────
            elif node.type == "short_var_declaration" and current_fn:
                left = node.child_by_field_name("left")
                if left:
                    var_name = self._node_text(left, src_bytes)
                    ctx.variables.append(VariableScope(
                        name=var_name or "?",
                        var_type="inferred",
                        function=current_fn,
                        declared_line=node.start_point[0] + 1,
                    ))

            # ── Unsafe pointer usage ─────────────────────────────────────
            elif node.type == "qualified_type":
                if "unsafe" in (self._node_text(node, src_bytes) or ""):
                    if current_fn and current_fn in ctx.functions:
                        ctx.functions[current_fn].pointer_ops += 1

            for child in node.children:
                walk(child, current_fn)

        walk(root)

    def _go_params(self, fn_node: "Node", src: bytes) -> list[str]:
        params_node = fn_node.child_by_field_name("parameters")
        if not params_node:
            return []
        return [
            self._node_text(child, src)
            for child in params_node.children
            if child.type not in ("(", ")", ",")
        ]

    def _go_has_extern_input(self, fn_node: "Node", src: bytes) -> bool:
        text = self._node_text(fn_node, src) or ""
        return any(kw in text for kw in ("os.Args", "bufio.NewReader", "fmt.Scan", "http.Request", "os.Stdin"))

    # ── Java Parser ───────────────────────────────────────────────────────

    def _parse_java(self, root: "Node", source: str, lines: list[str], ctx: CodeContext) -> None:
        src_bytes = source.encode("utf-8")

        def walk(node: "Node", current_fn: Optional[str] = None):
            # ── Method declaration ───────────────────────────────────────
            if node.type in ("method_declaration", "constructor_declaration"):
                name_node = node.child_by_field_name("name")
                fn_name = self._node_text(name_node, src_bytes)
                if fn_name:
                    fn_info = FunctionInfo(
                        name=fn_name,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        params=self._java_params(node, src_bytes),
                        loop_depth=self._max_loop_depth(node),
                        is_entry=fn_name in JAVA_ENTRY_POINTS,
                        extern_input=self._java_has_extern_input(node, src_bytes),
                    )
                    ctx.functions[fn_name] = fn_info
                    if fn_name in JAVA_ENTRY_POINTS:
                        ctx.entry_points.append(fn_name)
                    current_fn = fn_name

            # ── Call expression ──────────────────────────────────────────
            elif node.type == "method_invocation":
                name_node = node.child_by_field_name("name")
                callee = self._node_text(name_node, src_bytes)
                if callee and current_fn:
                    line = node.start_point[0] + 1
                    ctx.call_sites.append(CallSite(
                        caller=current_fn, callee=callee, line=line
                    ))
                    if current_fn in ctx.functions:
                        if callee not in ctx.functions[current_fn].calls:
                            ctx.functions[current_fn].calls.append(callee)

            # ── Variable declaration ─────────────────────────────────────
            elif node.type in ("local_variable_declaration", "field_declaration") and current_fn:
                type_node = node.child_by_field_name("type")
                type_text = self._node_text(type_node, src_bytes) or ""
                
                for child in node.children:
                    if child.type == "variable_declarator":
                        name_node = child.child_by_field_name("name")
                        var_name = self._node_text(name_node, src_bytes)
                        if var_name:
                            ctx.variables.append(VariableScope(
                                name=var_name,
                                var_type=type_text,
                                function=current_fn,
                                declared_line=node.start_point[0] + 1,
                                is_array="[]" in type_text,
                            ))

            for child in node.children:
                walk(child, current_fn)

        walk(root)

    def _java_params(self, fn_node: "Node", src: bytes) -> list[str]:
        params_node = fn_node.child_by_field_name("parameters")
        if not params_node:
            return []
        params = []
        for child in params_node.children:
            if child.type == "formal_parameter":
                params.append(self._node_text(child, src) or "")
        return params

    def _java_has_extern_input(self, fn_node: "Node", src: bytes) -> bool:
        text = self._node_text(fn_node, src) or ""
        return any(kw in text for kw in ("Scanner", "System.in", "HttpRequest", "HttpServletRequest", "args"))

    # ── C++ Parser ────────────────────────────────────────────────────────

    def _parse_cpp(self, root: "Node", source: str, lines: list[str], ctx: CodeContext) -> None:
        src_bytes = source.encode("utf-8")

        def walk(node: "Node", current_fn: Optional[str] = None):
            # ── Function definition ──────────────────────────────────────
            if node.type == "function_definition":
                fn_name = self._cpp_function_name(node, src_bytes)
                if fn_name:
                    fn_info = FunctionInfo(
                        name=fn_name,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        params=self._cpp_params(node, src_bytes),
                        loop_depth=self._max_loop_depth(node),
                        is_entry=fn_name.split("::")[-1] in CPP_ENTRY_POINTS,
                        extern_input=self._cpp_has_extern_input(node, src_bytes),
                    )
                    ctx.functions[fn_name] = fn_info
                    if fn_name.split("::")[-1] in CPP_ENTRY_POINTS:
                        ctx.entry_points.append(fn_name)
                    current_fn = fn_name

            # ── Call expression ──────────────────────────────────────────
            elif node.type == "call_expression":
                callee_node = node.child_by_field_name("function")
                callee = self._node_text(callee_node, src_bytes)
                if callee and current_fn:
                    line = node.start_point[0] + 1
                    args = self._cpp_call_args(node, src_bytes)
                    ctx.call_sites.append(CallSite(
                        caller=current_fn, callee=callee, line=line, args=args
                    ))
                    if current_fn in ctx.functions:
                        if callee not in ctx.functions[current_fn].calls:
                            ctx.functions[current_fn].calls.append(callee)
                            
                    # Track frees (heuristically matching args)
                    if callee in CPP_FREE_CALLS and args:
                        freed_var = args[0].strip("&* ")
                        for alloc in ctx.allocations:
                            if alloc.function == current_fn and not alloc.freed:
                                alloc.freed = True
                                alloc.free_line = line
                                break

            # Track new allocations
            elif node.type == "new_expression" and current_fn:
                ctx.allocations.append(AllocationSite(
                    function=current_fn, line=node.start_point[0] + 1, alloc_type="new"
                ))

            # ── Variable declaration ─────────────────────────────────────
            elif node.type == "declaration" and current_fn:
                self._cpp_extract_variables(node, src_bytes, current_fn, ctx)
                
            # Pointer arithmetic / array subscript
            elif node.type in ("pointer_expression", "subscript_expression"):
                if current_fn and current_fn in ctx.functions:
                    ctx.functions[current_fn].pointer_ops += 1

            for child in node.children:
                walk(child, current_fn)

        walk(root)

    def _cpp_function_name(self, node: "Node", src: bytes) -> Optional[str]:
        declarator = node.child_by_field_name("declarator")
        if not declarator: return None
        # In C++, a function_declarator names the function, but it could be wrapped in other declarators
        while declarator and declarator.type in ("pointer_declarator", "reference_declarator"):
            declarator = declarator.child_by_field_name("declarator")
            
        if declarator and declarator.type == "function_declarator":
            name_node = declarator.child_by_field_name("declarator")
            return self._node_text(name_node, src)
        return self._node_text(declarator, src)
        
    def _cpp_params(self, fn_node: "Node", src: bytes) -> list[str]:
        # similar to C
        params = []
        declarator = fn_node.child_by_field_name("declarator")
        while declarator and declarator.type in ("pointer_declarator", "reference_declarator"):
            declarator = declarator.child_by_field_name("declarator")
            
        if declarator and declarator.type == "function_declarator":
            params_node = declarator.child_by_field_name("parameters")
            if params_node:
                for child in params_node.children:
                    if child.type == "parameter_declaration":
                        params.append(self._node_text(child, src) or "")
        return params

    def _cpp_call_args(self, call_node: "Node", src: bytes) -> list[str]:
        args_node = call_node.child_by_field_name("arguments")
        if not args_node: return []
        return [
            self._node_text(child, src) or ""
            for child in args_node.children
            if child.type not in ("(", ")", ",")
        ]

    def _cpp_extract_variables(self, decl_node: "Node", src: bytes, fn: str, ctx: CodeContext) -> None:
        type_text = ""
        type_node = decl_node.child_by_field_name("type")
        if type_node:
            type_text = self._node_text(type_node, src) or ""

        for child in decl_node.children:
            if child.type in ("init_declarator", "identifier", "pointer_declarator", "array_declarator", "reference_declarator"):
                name = self._node_text(child, src)
                if name:
                    is_ptr   = "*" in name or type_text.count("*") > 0
                    is_arr   = "[" in name
                    ctx.variables.append(VariableScope(
                        name=name.strip("*& "),
                        var_type=type_text,
                        function=fn,
                        declared_line=decl_node.start_point[0] + 1,
                        is_pointer=is_ptr,
                        is_array=is_arr,
                    ))

    def _cpp_has_extern_input(self, fn_node: "Node", src: bytes) -> bool:
        text = self._node_text(fn_node, src) or ""
        return any(kw in text for kw in ("std::cin", "cin", "scanf", "gets", "argv", "read("))

    # ── Shared Utilities ──────────────────────────────────────────────────

    def _node_text(self, node: Optional["Node"], src: bytes) -> Optional[str]:
        if node is None:
            return None
        try:
            return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()
        except Exception:
            return None

    def _max_loop_depth(self, node: "Node", current_depth: int = 0) -> int:
        """Recursively find maximum loop nesting depth under this node."""
        LOOP_TYPES = {
            "for_statement", "while_statement", "do_statement",
            "for_in_statement", "for_expression",  # Python/Go variants
        }
        max_depth = current_depth
        if node.type in LOOP_TYPES:
            current_depth += 1
            max_depth = current_depth
        for child in node.children:
            max_depth = max(max_depth, self._max_loop_depth(child, current_depth))
        return max_depth

    def _node_to_dict(self, node: "Node", source: str, depth: int = 0, max_depth: int = 6) -> dict:
        """
        Serialize AST to a JSON-compatible dict.
        Capped at max_depth to prevent massive files on large codebases.
        """
        if depth > max_depth:
            return {"type": node.type, "truncated": True}

        result = {
            "type": node.type,
            "start": list(node.start_point),
            "end":   list(node.end_point),
        }

        # Only include text for leaf nodes
        if not node.children:
            try:
                text = source.encode()[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                if text.strip():
                    result["text"] = text
            except Exception:
                pass

        if node.children:
            result["children"] = [
                self._node_to_dict(child, source, depth + 1, max_depth)
                for child in node.children
            ]

        return result