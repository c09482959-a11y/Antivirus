"""Bounded canonical Python/Ren'Py static-program-analysis frontend.

The frontend emits only language-neutral physical operations and value-flow
relations.  It does not map ATT&CK techniques, assign probabilities, execute
source, import scanned modules, or replace the existing lexical scanners.
"""
from __future__ import annotations

from dataclasses import dataclass
import ast
from io import BytesIO
import hashlib
import json
import sys
import tokenize
from typing import Iterable

from Virus_Scan.contracts.artifact_read_snapshot import (
    ArtifactReadSnapshot,
    require_artifact_read_snapshot,
)
from Virus_Scan.contracts.static_program_analysis import (
    static_artifact_identity,
    STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    StaticFlowEdge,
    StaticOperation,
    StaticProgramAnalysis,
    StaticSourceLocation,
)
from Virus_Scan.storage import scan_cache_repository

PYTHON_RENPY_FRONTEND_SCHEMA_VERSION = "python_renpy_static_frontend_v6"
PYTHON_RENPY_MAX_SOURCE_BYTES = 1_500_000
PYTHON_RENPY_MAX_AST_NODES = 100_000
PYTHON_RENPY_MAX_FUNCTIONS = 2_048
PYTHON_RENPY_MAX_OPERATIONS = 4_096
PYTHON_RENPY_MAX_FLOW_EDGES = 4_096
PYTHON_RENPY_MAX_UNRESOLVED = 256
PYTHON_RENPY_MAX_CONSTANT_TEXT = 4_096
PYTHON_RENPY_MAX_VALUE_ORIGINS = 32

_DYNAMIC_CALLS = frozenset({
    "eval", "exec", "compile", "__import__", "importlib.import_module",
    "getattr", "setattr", "delattr", "globals", "locals",
})
_BUILTIN_CALLS = frozenset({
    "open", "eval", "exec", "compile", "__import__", "getattr", "setattr",
    "delattr", "globals", "locals", "str", "bytes", "bytearray", "memoryview",
    "list", "tuple", "dict", "set", "frozenset",
})
_FLOW_PASSTHROUGH_CALLS = frozenset({
    "str", "bytes", "bytearray", "memoryview", "list", "tuple",
})
_FLOW_PASSTHROUGH_METHODS = frozenset({
    "encode", "decode", "fetchone", "fetchmany", "fetchall", "strip", "lstrip",
    "rstrip", "lower", "upper", "casefold", "replace", "join",
})
def _call_implies_windows_platform(call_name: str) -> bool:
    """Return whether a resolved call is intrinsically Windows-specific.

    These predicates describe Python API grammar rather than mutable scanner
    policy, so they remain explicit implementation logic instead of a hidden
    module-level policy table.
    """
    return (
        call_name.startswith("ctypes.windll.")
        or call_name.startswith("ctypes.WinDLL")
        or call_name.startswith("win32api.")
        or call_name.startswith("win32process.")
        or call_name.startswith("win32crypt.")
        or call_name.startswith("winreg.")
    )


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    return hashlib.sha256(encoded).hexdigest()


PYTHON_RENPY_FRONTEND_DIGEST = _canonical_digest({
    "ast_runtime": [sys.version_info.major, sys.version_info.minor],
    "frontend_schema": PYTHON_RENPY_FRONTEND_SCHEMA_VERSION,
    "ir_schema": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    "ir_schema_digest": STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    "limits": {
        "ast_nodes": PYTHON_RENPY_MAX_AST_NODES,
        "flow_edges": PYTHON_RENPY_MAX_FLOW_EDGES,
        "functions": PYTHON_RENPY_MAX_FUNCTIONS,
        "operations": PYTHON_RENPY_MAX_OPERATIONS,
        "source_bytes": PYTHON_RENPY_MAX_SOURCE_BYTES,
    },
    "renpy_normalizer": "renpy_python_blocks_v1",
})
def python_renpy_analysis_dependency_digest() -> str:
    return PYTHON_RENPY_FRONTEND_DIGEST


def _identity(prefix: str, *parts: object) -> str:
    return prefix + _canonical_digest([str(part) for part in parts])[:40]


@dataclass(slots=True)
class _ValueState:
    value_id: str
    resolved: object = None
    origins: tuple[int, ...] = ()


@dataclass(slots=True)
class _OperationDraft:
    kind: str
    node: ast.AST
    function_key: str
    block_key: str
    ordinal: int
    reachability: str
    provenance: str
    platform: str
    target_resource: str
    input_values: tuple[str, ...]
    output_values: tuple[str, ...]
    resolved_arguments: dict[str, object]
    resolution: str
    limitations: tuple[str, ...]
    integrity: str
    flow_identity: str = ""
    operation: StaticOperation | None = None


@dataclass(slots=True)
class _EdgeDraft:
    kind: str
    flow_identity: str
    source_value_id: str
    target_value_id: str
    source_draft: int | None = None
    target_draft: int | None = None
    resolution: str = "resolved"
    limitations: tuple[str, ...] = ()
    integrity: str = "verified"


@dataclass(slots=True)
class _FunctionInfo:
    key: str
    name: str
    node: ast.AST
    parent_key: str
    reachability: str = "locally_reachable"
    is_method: bool = False


@dataclass(frozen=True, slots=True)
class _CallTarget:
    kind: str
    canonical_name: str = ""
    local_function_key: str = ""


@dataclass(frozen=True, slots=True)
class PythonRenpyAnalysisResult:
    analysis: StaticProgramAnalysis
    cache_source: str


class _Analyzer:
    def __init__(self, *, snapshot: ArtifactReadSnapshot, language: str, source: str) -> None:
        self.snapshot = snapshot
        self.language = language
        self.source = source
        self.locator = static_artifact_identity(snapshot.content_sha256)
        self.module_key = "<module>"
        self.functions: dict[str, _FunctionInfo] = {}
        self.function_bindings_by_scope: dict[str, dict[str, list[str]]] = {self.module_key: {}}
        self.non_import_bindings_by_scope: dict[str, set[str]] = {self.module_key: set()}
        self.import_aliases_by_function: dict[str, dict[str, str]] = {self.module_key: {}}
        self.ambiguous_import_aliases_by_function: dict[str, set[str]] = {self.module_key: set()}
        self.direct_local_calls: dict[str, dict[str, str]] = {self.module_key: {}}
        self.local_call_argument_states: dict[str, dict[str, list[_ValueState]]] = {}
        self.operation_drafts: list[_OperationDraft] = []
        self.edge_drafts: list[_EdgeDraft] = []
        self.unresolved: set[str] = set()
        self.limitations: set[str] = set()
        self._ordinal = 0

    def analyze(self, tree: ast.AST) -> StaticProgramAnalysis:
        self._collect_functions_and_imports(tree)
        self._mark_entrypoint_functions(tree)
        module_env: dict[str, _ValueState] = {}
        body = tree.body if isinstance(tree, ast.Module) else []
        self._visit_statements(
            body,
            function_key=self.module_key,
            block_key="module_entry",
            reachability="entrypoint_reachable",
            env=module_env,
        )
        for key in self._function_analysis_order():
            info = self.functions[key]
            if not isinstance(info.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            env = self._function_parameter_env(key, info.node)
            self._visit_statements(
                info.node.body,
                function_key=key,
                block_key="function_entry",
                reachability=info.reachability,
                env=env,
            )
        return self._finalize()

    def _collect_functions_and_imports(self, tree: ast.AST) -> None:
        function_stack: list[str] = []

        class Collector(ast.NodeVisitor):
            def __init__(self, owner: _Analyzer) -> None:
                self.owner = owner

            def _scope(self) -> str:
                return function_stack[-1] if function_stack else self.owner.module_key

            def visit_Name(self, node: ast.Name) -> None:
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    self.owner.non_import_bindings_by_scope.setdefault(self._scope(), set()).add(node.id)

            def visit_Import(self, node: ast.Import) -> None:
                scope = self._scope()
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    self.owner._register_import_alias(scope, bound, alias.name)

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                scope = self._scope()
                module = node.module or ""
                for alias in node.names:
                    bound = alias.asname or alias.name
                    self.owner._register_import_alias(
                        scope,
                        bound,
                        (module + "." + alias.name).strip("."),
                    )

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                scope = self._scope()
                self.owner.non_import_bindings_by_scope.setdefault(scope, set()).add(node.name)
                for statement in node.body:
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._visit_function(statement, statement.name, is_method=True, class_name=node.name)
                    elif isinstance(statement, ast.ClassDef):
                        self.visit_ClassDef(statement)

            def _visit_function(
                self,
                node: ast.FunctionDef | ast.AsyncFunctionDef,
                name: str,
                *,
                is_method: bool = False,
                class_name: str = "",
            ) -> None:
                if len(self.owner.functions) >= PYTHON_RENPY_MAX_FUNCTIONS:
                    self.owner.limitations.add("function_limit_exceeded")
                    return
                parent = self._scope()
                line = getattr(node, "lineno", 0)
                qualifier = ("<class:" + class_name + ">.") if is_method else ""
                key = parent + "." + qualifier + name + "@" + str(line)
                info = _FunctionInfo(
                    key=key,
                    name=name,
                    node=node,
                    parent_key=parent,
                    is_method=is_method,
                )
                self.owner.functions[key] = info
                self.owner.function_bindings_by_scope.setdefault(key, {})
                self.owner.non_import_bindings_by_scope.setdefault(key, set())
                self.owner.import_aliases_by_function.setdefault(key, {})
                self.owner.ambiguous_import_aliases_by_function.setdefault(key, set())
                self.owner.direct_local_calls.setdefault(key, {})
                if not is_method:
                    self.owner.function_bindings_by_scope.setdefault(parent, {}).setdefault(name, []).append(key)
                args = node.args
                for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
                    self.owner.non_import_bindings_by_scope[key].add(arg.arg)
                if args.vararg is not None:
                    self.owner.non_import_bindings_by_scope[key].add(args.vararg.arg)
                if args.kwarg is not None:
                    self.owner.non_import_bindings_by_scope[key].add(args.kwarg.arg)
                function_stack.append(key)
                self.generic_visit(node)
                function_stack.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._visit_function(node, node.name)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._visit_function(node, node.name)

        Collector(self).visit(tree)

    @staticmethod
    def _reachability_rank(value: str) -> int:
        return {
            "unreachable": 0,
            "locally_reachable": 0,
            "conditionally_reachable": 1,
            "entrypoint_reachable": 2,
        }.get(value, 0)

    @staticmethod
    def _compose_reachability(caller: str, edge: str) -> str:
        if caller == "unreachable" or edge == "unreachable":
            return "unreachable"
        if caller == "conditionally_reachable" or edge == "conditionally_reachable":
            return "conditionally_reachable"
        if caller == "entrypoint_reachable" and edge == "entrypoint_reachable":
            return "entrypoint_reachable"
        return "locally_reachable"

    @staticmethod
    def _constant_branch_state(node: ast.AST) -> bool | None:
        if isinstance(node, ast.Constant) and type(node.value) in (bool, int, str):
            return bool(node.value)
        if isinstance(node, ast.Constant) and node.value is None:
            return False
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            nested = _Analyzer._constant_branch_state(node.operand)
            return None if nested is None else not nested
        return None

    def _resolve_local_function_key(
        self,
        name: str,
        function_key: str,
        *,
        record_ambiguity: bool,
    ) -> str:
        for scope in self._scope_chain(function_key):
            candidates = tuple(self.function_bindings_by_scope.get(scope, {}).get(name, ()))
            has_other_binding = (
                name in self.non_import_bindings_by_scope.get(scope, set())
                or name in self.import_aliases_by_function.get(scope, {})
                or name in self.ambiguous_import_aliases_by_function.get(scope, set())
            )
            if candidates:
                if len(candidates) == 1 and not has_other_binding:
                    return candidates[0]
                if record_ambiguity:
                    self.unresolved.add("ambiguous_function_resolution:" + name[:200])
                    self.limitations.add("ambiguous_function_resolution")
                return ""
            if has_other_binding:
                return ""
        return ""

    def _record_direct_local_call(self, current: str, target: str, reachability: str) -> None:
        if not target or reachability == "unreachable":
            return
        calls = self.direct_local_calls.setdefault(current, {})
        previous = calls.get(target, "unreachable")
        if self._reachability_rank(reachability) > self._reachability_rank(previous):
            calls[target] = reachability

    def _scan_scope_calls(
        self,
        statements: Iterable[ast.stmt],
        *,
        current: str,
        reachability: str,
    ) -> None:
        owner = self

        class CallCollector(ast.NodeVisitor):
            def __init__(self, state: str) -> None:
                self.state = state

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                return

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                return

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                return

            def visit_Call(self, node: ast.Call) -> None:
                if isinstance(node.func, ast.Name):
                    target = owner._resolve_local_function_key(
                        node.func.id,
                        current,
                        record_ambiguity=True,
                    )
                    owner._record_direct_local_call(current, target, self.state)
                self.generic_visit(node)

        def scan_expression(node: ast.AST | None, state: str) -> None:
            if node is not None and state != "unreachable":
                CallCollector(state).visit(node)

        active = reachability
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in statement.decorator_list:
                    scan_expression(decorator, active)
                for default in (*statement.args.defaults, *statement.args.kw_defaults):
                    scan_expression(default, active)
                continue
            if isinstance(statement, ast.ClassDef):
                for decorator in statement.decorator_list:
                    scan_expression(decorator, active)
                for base in statement.bases:
                    scan_expression(base, active)
                continue
            if isinstance(statement, (ast.Return, ast.Raise)):
                scan_expression(statement.value if isinstance(statement, ast.Return) else statement.exc, active)
                active = "unreachable"
                continue
            if isinstance(statement, ast.If):
                scan_expression(statement.test, active)
                condition = self._constant_branch_state(statement.test)
                if condition is True:
                    body_state, else_state = active, "unreachable"
                elif condition is False:
                    body_state, else_state = "unreachable", active
                else:
                    conditional = "unreachable" if active == "unreachable" else "conditionally_reachable"
                    body_state = else_state = conditional
                self._scan_scope_calls(statement.body, current=current, reachability=body_state)
                self._scan_scope_calls(statement.orelse, current=current, reachability=else_state)
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                scan_expression(statement.iter if isinstance(statement, (ast.For, ast.AsyncFor)) else statement.test, active)
                state = "unreachable" if active == "unreachable" else "conditionally_reachable"
                if isinstance(statement, ast.While):
                    condition = self._constant_branch_state(statement.test)
                    if condition is False:
                        state = "unreachable"
                self._scan_scope_calls(statement.body, current=current, reachability=state)
                self._scan_scope_calls(statement.orelse, current=current, reachability=state if state != "unreachable" else active)
                continue
            if isinstance(statement, ast.Try):
                self._scan_scope_calls(statement.body, current=current, reachability=active)
                branch_state = "unreachable" if active == "unreachable" else "conditionally_reachable"
                for handler in statement.handlers:
                    scan_expression(handler.type, branch_state)
                    self._scan_scope_calls(handler.body, current=current, reachability=branch_state)
                self._scan_scope_calls(statement.orelse, current=current, reachability=branch_state)
                self._scan_scope_calls(statement.finalbody, current=current, reachability=active)
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    scan_expression(item.context_expr, active)
                self._scan_scope_calls(statement.body, current=current, reachability=active)
                continue
            if isinstance(statement, ast.Match):
                scan_expression(statement.subject, active)
                branch_state = "unreachable" if active == "unreachable" else "conditionally_reachable"
                for case in statement.cases:
                    scan_expression(case.guard, branch_state)
                    self._scan_scope_calls(case.body, current=current, reachability=branch_state)
                continue
            scan_expression(statement, active)

    def _mark_entrypoint_functions(self, tree: ast.AST) -> None:
        if isinstance(tree, ast.Module):
            self._scan_scope_calls(
                tree.body,
                current=self.module_key,
                reachability="entrypoint_reachable",
            )
        for key, info in self.functions.items():
            if isinstance(info.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._scan_scope_calls(
                    info.node.body,
                    current=key,
                    reachability="entrypoint_reachable",
                )

        queue: list[str] = [self.module_key]
        visited: set[str] = set()
        while queue:
            caller = queue.pop(0)
            if caller in visited and caller != self.module_key:
                continue
            visited.add(caller)
            caller_state = (
                "entrypoint_reachable"
                if caller == self.module_key
                else self.functions[caller].reachability
            )
            for target, edge_state in sorted(self.direct_local_calls.get(caller, {}).items()):
                composed = self._compose_reachability(caller_state, edge_state)
                if composed == "unreachable":
                    continue
                info = self.functions[target]
                if self._reachability_rank(composed) > self._reachability_rank(info.reachability):
                    info.reachability = composed
                    queue.append(target)

    def _function_analysis_order(self) -> tuple[str, ...]:
        order: list[str] = []
        queue = [
            target
            for target, edge_state in sorted(self.direct_local_calls.get(self.module_key, {}).items())
            if edge_state != "unreachable"
        ]
        seen: set[str] = set()
        while queue:
            key = queue.pop(0)
            if key in seen:
                continue
            seen.add(key)
            order.append(key)
            queue.extend(
                target
                for target, edge_state in sorted(self.direct_local_calls.get(key, {}).items())
                if edge_state != "unreachable"
            )
        order.extend(key for key in sorted(self.functions) if key not in seen)
        return tuple(order)

    def _function_parameter_env(
        self,
        key: str,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> dict[str, _ValueState]:
        env: dict[str, _ValueState] = {}
        actuals_by_name = self.local_call_argument_states.get(key, {})
        parameters = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        for arg in parameters:
            parameter_id = _identity("val_", self.snapshot.content_sha256, key, "param", arg.arg)
            actuals = actuals_by_name.get(arg.arg, [])
            origins = tuple(dict.fromkeys(
                origin
                for state in actuals
                for origin in state.origins
            ))[-PYTHON_RENPY_MAX_VALUE_ORIGINS:]
            resolved_values = [state.resolved for state in actuals]
            resolved = (
                resolved_values[0]
                if resolved_values
                and all(type(value) is type(resolved_values[0]) and value == resolved_values[0] for value in resolved_values)
                else None
            )
            for state in actuals:
                if not state.origins:
                    continue
                flow = _identity(
                    "flow_",
                    self.snapshot.content_sha256,
                    state.value_id,
                    parameter_id,
                    key,
                    arg.arg,
                )
                self._append_edge(_EdgeDraft(
                    "argument",
                    flow,
                    state.value_id,
                    parameter_id,
                    source_draft=state.origins[-1],
                ))
            env[arg.arg] = _ValueState(parameter_id, resolved, origins)
        if node.args.vararg is not None:
            name = node.args.vararg.arg
            env[name] = _ValueState(_identity("val_", self.snapshot.content_sha256, key, "param", name))
        if node.args.kwarg is not None:
            name = node.args.kwarg.arg
            env[name] = _ValueState(_identity("val_", self.snapshot.content_sha256, key, "param", name))
        return env

    def _record_local_call_arguments(
        self,
        target_key: str,
        node: ast.Call,
        arg_states: list[_ValueState | None],
        kw_states: dict[str, _ValueState | None],
    ) -> None:
        info = self.functions.get(target_key)
        if info is None or not isinstance(info.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return
        target = self.local_call_argument_states.setdefault(target_key, {})
        positional = (*info.node.args.posonlyargs, *info.node.args.args)
        for index, state in enumerate(arg_states):
            if state is None or index >= len(positional):
                continue
            target.setdefault(positional[index].arg, []).append(state)
        positional_names = {arg.arg for arg in positional}
        keyword_only_names = {arg.arg for arg in info.node.args.kwonlyargs}
        for name, state in kw_states.items():
            if state is None or name == "**":
                continue
            if name in positional_names or name in keyword_only_names:
                target.setdefault(name, []).append(state)

    def _visit_statements(
        self,
        statements: Iterable[ast.stmt],
        *,
        function_key: str,
        block_key: str,
        reachability: str,
        env: dict[str, _ValueState],
    ) -> None:
        active = reachability
        for index, statement in enumerate(statements):
            if len(self.operation_drafts) >= PYTHON_RENPY_MAX_OPERATIONS:
                self.limitations.add("operation_limit_exceeded")
                return
            child_block = block_key + "." + str(index)
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom, ast.Pass)):
                continue
            if isinstance(statement, (ast.Return, ast.Raise)):
                if isinstance(statement, ast.Return) and statement.value is not None:
                    self._visit_expression(statement.value, function_key, child_block, active, env, assigned_name="")
                active = "unreachable"
                continue
            if isinstance(statement, ast.If):
                condition = self._constant(statement.test, env, function_key)
                self._visit_expression(statement.test, function_key, child_block + ".condition", active, env, assigned_name="")
                if condition is True:
                    body_state, else_state = active, "unreachable"
                elif condition is False:
                    body_state, else_state = "unreachable", active
                else:
                    body_state = else_state = "conditionally_reachable" if active != "unreachable" else "unreachable"
                self._visit_statements(statement.body, function_key=function_key, block_key=child_block + ".if", reachability=body_state, env=dict(env))
                self._visit_statements(statement.orelse, function_key=function_key, block_key=child_block + ".else", reachability=else_state, env=dict(env))
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                test = statement.iter if isinstance(statement, (ast.For, ast.AsyncFor)) else statement.test
                self._visit_expression(test, function_key, child_block + ".loop_test", active, env, assigned_name="")
                loop_state = "conditionally_reachable" if active != "unreachable" else "unreachable"
                self._visit_statements(statement.body, function_key=function_key, block_key=child_block + ".loop", reachability=loop_state, env=dict(env))
                self._visit_statements(statement.orelse, function_key=function_key, block_key=child_block + ".loop_else", reachability=loop_state, env=dict(env))
                continue
            if isinstance(statement, ast.Try):
                branch_state = "conditionally_reachable" if active != "unreachable" else "unreachable"
                self._visit_statements(statement.body, function_key=function_key, block_key=child_block + ".try", reachability=active, env=dict(env))
                for handler_index, handler in enumerate(statement.handlers):
                    self._visit_statements(handler.body, function_key=function_key, block_key=child_block + ".except" + str(handler_index), reachability=branch_state, env=dict(env))
                self._visit_statements(statement.orelse, function_key=function_key, block_key=child_block + ".try_else", reachability=branch_state, env=dict(env))
                self._visit_statements(statement.finalbody, function_key=function_key, block_key=child_block + ".finally", reachability=active, env=dict(env))
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                for item_index, item in enumerate(statement.items):
                    names = self._target_names(item.optional_vars) if item.optional_vars is not None else []
                    assigned = names[0] if len(names) == 1 else ""
                    state = self._visit_expression(
                        item.context_expr,
                        function_key,
                        child_block + ".with" + str(item_index),
                        active,
                        env,
                        assigned_name=assigned,
                    )
                    for name in names:
                        target_id = _identity(
                            "val_",
                            self.snapshot.content_sha256,
                            function_key,
                            name,
                            getattr(statement, "lineno", 0),
                            "with_binding",
                        )
                        if state is None:
                            state = _ValueState(
                                target_id,
                                self._constant(item.context_expr, env, function_key),
                                (),
                            )
                        elif state.value_id != target_id:
                            flow = _identity(
                                "flow_",
                                self.snapshot.content_sha256,
                                function_key,
                                state.value_id,
                                target_id,
                                getattr(statement, "lineno", 0),
                                "with_binding",
                            )
                            self._append_edge(
                                _EdgeDraft(
                                    "assignment",
                                    flow,
                                    state.value_id,
                                    target_id,
                                    source_draft=state.origins[-1] if state.origins else None,
                                )
                            )
                            state = _ValueState(target_id, state.resolved, state.origins)
                        env[name] = state
                self._visit_statements(
                    statement.body,
                    function_key=function_key,
                    block_key=child_block + ".with_body",
                    reachability=active,
                    env=env,
                )
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = statement.value
                names = self._assignment_names(statement)
                assigned = names[0] if len(names) == 1 else ""
                state = self._visit_expression(value, function_key, child_block, active, env, assigned_name=assigned)
                for name in names:
                    target_id = _identity("val_", self.snapshot.content_sha256, function_key, name, getattr(statement, "lineno", 0))
                    if state is None:
                        state = _ValueState(target_id, self._constant(value, env, function_key), ())
                    elif state.value_id != target_id:
                        flow = _identity("flow_", self.snapshot.content_sha256, function_key, state.value_id, target_id, getattr(statement, "lineno", 0))
                        self._append_edge(_EdgeDraft("assignment", flow, state.value_id, target_id, source_draft=state.origins[-1] if state.origins else None))
                        state = _ValueState(target_id, state.resolved, state.origins)
                    env[name] = state
                continue
            if isinstance(statement, ast.Expr):
                self._visit_expression(statement.value, function_key, child_block, active, env, assigned_name="")
                continue
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, ast.expr):
                    self._visit_expression(child, function_key, child_block, active, env, assigned_name="")

    def _visit_expression(
        self,
        expression: ast.AST,
        function_key: str,
        block_key: str,
        reachability: str,
        env: dict[str, _ValueState],
        *,
        assigned_name: str,
    ) -> _ValueState | None:
        if isinstance(expression, ast.Call):
            return self._emit_call(expression, function_key, block_key, reachability, env, assigned_name)
        if isinstance(expression, ast.Name):
            return env.get(expression.id)
        resolved = self._constant(expression, env, function_key)
        if resolved is not None:
            value_id = _identity("val_", self.snapshot.content_sha256, function_key, "literal", getattr(expression, "lineno", 0), repr(resolved))
            return _ValueState(value_id, resolved, ())
        for child in ast.iter_child_nodes(expression):
            if isinstance(child, ast.Call):
                self._visit_expression(child, function_key, block_key + ".child", reachability, env, assigned_name="")
        return None

    def _emit_call(
        self,
        node: ast.Call,
        function_key: str,
        block_key: str,
        reachability: str,
        env: dict[str, _ValueState],
        assigned_name: str,
    ) -> _ValueState | None:
        receiver_state: _ValueState | None = None
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            receiver_state = self._visit_expression(
                node.func.value,
                function_key,
                block_key + ".receiver",
                reachability,
                env,
                assigned_name="<receiver>",
            )
            target = _CallTarget("receiver", "__receiver__." + node.func.attr)
        else:
            target = self._resolve_call_target(node.func, function_key, env)

        arg_states = [
            self._visit_expression(
                item,
                function_key,
                block_key + ".arg" + str(index),
                reachability,
                env,
                assigned_name="<argument_" + str(index) + ">" if isinstance(item, ast.Call) else "",
            )
            for index, item in enumerate(node.args)
        ]
        kw_states = {
            item.arg or "**": self._visit_expression(
                item.value,
                function_key,
                block_key + ".kw_" + (item.arg or "expanded"),
                reachability,
                env,
                assigned_name="<keyword_" + (item.arg or "expanded") + ">" if isinstance(item.value, ast.Call) else "",
            )
            for item in node.keywords
        }
        if receiver_state is None:
            receiver_state = self._receiver_state(node.func, env, function_key)
        input_states = [*arg_states, *kw_states.values()]
        if receiver_state is not None:
            input_states.insert(0, receiver_state)
        # One canonical value identity is one call input.  The same resolved
        # value can be reached through more than one syntactic route (for
        # example receiver/argument state); emitting it twice would mint two
        # identical StaticFlowEdge identities for one physical relation.
        unique_input_states: list[_ValueState | None] = []
        seen_input_value_ids: set[str] = set()
        for state in input_states:
            if state is None:
                continue
            if state.value_id in seen_input_value_ids:
                continue
            seen_input_value_ids.add(state.value_id)
            unique_input_states.append(state)
        input_states = unique_input_states
        upstream_origins = tuple(dict.fromkeys(
            origin
            for state in input_states
            if state is not None
            for origin in state.origins
        ))[-PYTHON_RENPY_MAX_VALUE_ORIGINS:]

        call_identity = target.canonical_name or target.local_function_key or "unresolved_call"
        output_id = _identity(
            "val_",
            self.snapshot.content_sha256,
            function_key,
            assigned_name or "call",
            getattr(node, "lineno", 0),
            call_identity,
        )

        if target.kind == "local_function":
            self._record_local_call_arguments(
                target.local_function_key,
                node,
                arg_states,
                kw_states,
            )
            if assigned_name and upstream_origins:
                self.unresolved.add(
                    "interprocedural_return_flow_unresolved:"
                    + self.functions[target.local_function_key].name[:160]
                )
            return _ValueState(output_id, None, ()) if assigned_name else None

        if target.kind == "unknown":
            self.unresolved.add("dynamic_call_target")
            if assigned_name and upstream_origins:
                self.unresolved.add("unresolved_return_flow")
            return _ValueState(output_id, None, ()) if assigned_name else None

        call_name = target.canonical_name
        if call_name in _DYNAMIC_CALLS or call_name.split(".")[-1] in _DYNAMIC_CALLS:
            self.unresolved.add("dynamic_construct:" + call_name[:200])

        resolved_args: dict[str, object] = {"call": call_name}
        for index, state in enumerate(arg_states):
            if state is not None and state.resolved is not None:
                resolved_args["arg" + str(index)] = self._json_value(state.resolved)
        for name, state in kw_states.items():
            if state is not None and state.resolved is not None:
                resolved_args["kw_" + name] = self._json_value(state.resolved)
        classifications = self._classify_call(
            call_name,
            resolved_args,
            receiver_state,
            positional_count=len(node.args),
            keyword_names=frozenset(
                item.arg for item in node.keywords if item.arg is not None
            ),
        )
        if not classifications:
            if assigned_name and upstream_origins and self._call_preserves_value_flow(
                target,
                call_name,
            ):
                return _ValueState(output_id, None, upstream_origins)
            if assigned_name and upstream_origins:
                self.unresolved.add("unresolved_return_flow:" + call_name[:160])
            return _ValueState(output_id, None, ()) if assigned_name else None

        inputs = tuple(dict.fromkeys(state.value_id for state in input_states if state is not None))
        output_ids = (output_id,) if assigned_name else ()
        created_indices: list[int] = []
        for kind, platform, target_text, extras, limitations in classifications:
            target_resource = (
                _identity("res_", self.snapshot.content_sha256, target_text)
                if target_text
                else self._inherited_target_resource(kind, arg_states)
            )
            index = self._append_operation(_OperationDraft(
                kind=kind,
                node=node,
                function_key=function_key,
                block_key=block_key,
                ordinal=self._next_ordinal(),
                reachability=reachability,
                provenance="static_control_flow",
                platform=platform,
                target_resource=target_resource,
                input_values=inputs,
                output_values=output_ids,
                resolved_arguments={**resolved_args, **extras},
                resolution="resolved" if target_text or resolved_args.keys() - {"call"} else "partial",
                limitations=limitations,
                integrity="verified" if reachability != "unresolved" else "partial",
            ))
            if index is not None:
                created_indices.append(index)
                if output_ids:
                    for state in input_states:
                        if state is None:
                            continue
                        flow = _identity("flow_", self.snapshot.content_sha256, state.value_id, output_id, index)
                        self._append_edge(_EdgeDraft(
                            "argument",
                            flow,
                            state.value_id,
                            output_id,
                            source_draft=state.origins[-1] if state.origins else None,
                            target_draft=index,
                        ))
        self._connect_sources_to_sinks(created_indices, input_states)
        origins = tuple(dict.fromkeys([*upstream_origins, *created_indices]))[-PYTHON_RENPY_MAX_VALUE_ORIGINS:]
        return _ValueState(output_id, None, origins) if output_ids else None

    @staticmethod
    def _call_preserves_value_flow(target: _CallTarget, call_name: str) -> bool:
        if target.kind == "builtin" and call_name in _FLOW_PASSTHROUGH_CALLS:
            return True
        return call_name.split(".")[-1].lower() in _FLOW_PASSTHROUGH_METHODS

    def _inherited_target_resource(
        self,
        operation_kind: str,
        arg_states: list[_ValueState | None],
    ) -> str:
        """Resolve one static resource identity through an exact handle origin."""
        handle_kinds = {
            "apc_execute", "context_execute", "memory_allocate", "memory_protect",
            "memory_read", "memory_write", "thread_execute",
        }
        if operation_kind not in handle_kinds or not arg_states or arg_states[0] is None:
            return ""
        resources = {
            self.operation_drafts[index].target_resource
            for index in arg_states[0].origins
            if 0 <= index < len(self.operation_drafts)
            and self.operation_drafts[index].kind == "process_open"
            and self.operation_drafts[index].target_resource
        }
        return next(iter(resources)) if len(resources) == 1 else ""

    def _receiver_state(
        self,
        function: ast.AST,
        env: dict[str, _ValueState],
        function_key: str,
    ) -> _ValueState | None:
        if isinstance(function, ast.Attribute):
            return self._expression_state(function.value, env, function_key)
        return None

    @staticmethod
    def _add_draft_limitation(draft: _OperationDraft, limitation: str) -> None:
        draft.limitations = tuple(dict.fromkeys((*draft.limitations, limitation)))
        draft.resolution = "partial"
        draft.integrity = "partial"

    def _connect_sources_to_sinks(
        self,
        sink_indices: list[int],
        input_states: list[_ValueState | None],
    ) -> None:
        sink_kinds = {
            "network_send",
            "network_upload",
            "serialize",
            "archive",
            "file_write",
            "decrypt",
            "decode",
            "decompress",
        }
        source_priority = {
            "credential_store_query": 0,
            "memory_read": 1,
            "database_query": 2,
            "decrypt": 3,
            "file_read": 4,
        }
        for sink_index in sink_indices:
            sink = self.operation_drafts[sink_index]
            if sink.kind not in sink_kinds:
                continue
            candidates: list[tuple[int, int, _ValueState]] = []
            for state in input_states:
                if state is None:
                    continue
                for source_index in state.origins:
                    if source_index >= len(self.operation_drafts):
                        continue
                    source = self.operation_drafts[source_index]
                    priority = source_priority.get(source.kind)
                    if priority is not None:
                        candidates.append((priority, source_index, state))
            if not candidates:
                continue
            existing_flows = {
                self.operation_drafts[source_index].flow_identity
                for _, source_index, _ in candidates
                if self.operation_drafts[source_index].flow_identity
            }
            if len(existing_flows) == 1:
                flow = next(iter(existing_flows))
                compatible = [item for item in candidates if self.operation_drafts[item[1]].flow_identity in {"", flow}]
                chosen = min(compatible, key=lambda item: (item[0], item[1]))
            else:
                best_priority = min(item[0] for item in candidates)
                best = [item for item in candidates if item[0] == best_priority]
                unique_sources = {item[1] for item in best}
                if len(unique_sources) != 1 or len(existing_flows) > 1:
                    self._add_draft_limitation(sink, "ambiguous_source_flow")
                    self.limitations.add("ambiguous_source_flow")
                    continue
                chosen = best[0]
                source_index = chosen[1]
                source = self.operation_drafts[source_index]
                flow = source.flow_identity or _identity(
                    "flow_",
                    self.snapshot.content_sha256,
                    source_index,
                    source.kind,
                    chosen[2].value_id,
                )
            source_index = chosen[1]
            source_state = chosen[2]
            source = self.operation_drafts[source_index]
            source.flow_identity = flow
            sink.flow_identity = flow
            source_value = source.output_values[0] if source.output_values else source_state.value_id
            self._append_edge(_EdgeDraft(
                "source_to_sink",
                flow,
                source_value,
                source_state.value_id,
                source_draft=source_index,
                target_draft=sink_index,
            ))

    def _classify_call(
        self,
        call_name: str,
        args: dict[str, object],
        receiver_state: _ValueState | None,
        *,
        positional_count: int,
        keyword_names: frozenset[str],
    ) -> list[tuple[str, str, str, dict[str, object], tuple[str, ...]]]:
        lower = call_name.lower()
        base = lower.split(".")[-1]
        arg0 = str(args.get("arg0", ""))
        target = arg0[:PYTHON_RENPY_MAX_CONSTANT_TEXT]
        receiver_kinds = {
            self.operation_drafts[index].kind
            for index in (() if receiver_state is None else receiver_state.origins)
            if 0 <= index < len(self.operation_drafts)
        }
        platform = "windows" if _call_implies_windows_platform(call_name) or any(
            token in lower
            for token in (
                "openprocess",
                "readprocessmemory",
                "writeprocessmemory",
                "virtualalloc",
                "virtualprotect",
                "createremotethread",
                "queueuserapc",
                "setthreadcontext",
                "resumethread",
                "cryptunprotectdata",
                "minidump",
            )
        ) else ""
        if lower in {
            "subprocess.popen",
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_output",
            "os.system",
            "os.popen",
        } and any(
            token in target.lower()
            for token in ("powershell", "pwsh", "cmd.exe", "cmd /c")
        ):
            platform = "windows"
        out: list[tuple[str, str, str, dict[str, object], tuple[str, ...]]] = []

        def add(
            kind: str,
            target_text: str = target,
            extra: dict[str, object] | None = None,
            limitations: tuple[str, ...] = (),
        ) -> None:
            out.append((kind, platform, target_text, {} if extra is None else extra, limitations))

        if lower in {"open", "io.open"}:
            mode = str(args.get("arg1", args.get("kw_mode", "r")))
            add("file_open", target, {"mode": mode})
            credential_family = self._credential_path(target)
            if credential_family:
                add("credential_store_discovery", target, {"resource_family": credential_family})
        if lower in {"pathlib.path.open"}:
            mode = str(args.get("arg0", args.get("kw_mode", "r")))
            add("file_open", "", {"mode": mode}, ("path_receiver_identity_unresolved",))
        if lower in {"pathlib.path.read_text", "pathlib.path.read_bytes"} or (
            base in {"read", "read_text", "read_bytes"} and "file_open" in receiver_kinds
        ):
            add("file_read", target)
        if lower in {"pathlib.path.write_text", "pathlib.path.write_bytes"} or (
            base in {"write", "write_text", "write_bytes"} and "file_open" in receiver_kinds
        ):
            add("file_write", target)
        if lower in {"sqlite3.connect", "apsw.connection"} or lower.endswith("sqlite.connect"):
            add("database_open", target, {"database_kind": "sqlite"})
            credential_family = self._credential_path(target)
            if credential_family:
                add("credential_store_discovery", target, {"resource_family": credential_family})
        if base in {"execute", "executemany", "executescript"} and "database_open" in receiver_kinds:
            add("database_query", arg0, {"query": arg0[:PYTHON_RENPY_MAX_CONSTANT_TEXT]})
            if any(term in arg0.lower() for term in (" logins", "login", "password", "credential", "cookies")):
                add("credential_store_query", arg0, {"query": arg0[:PYTHON_RENPY_MAX_CONSTANT_TEXT]})
        if lower in {
            "subprocess.popen",
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_output",
            "os.system",
            "os.popen",
        }:
            add("process_launch", target)
        if base == "openprocess" or lower in {"psutil.process", "win32api.openprocess"}:
            process_target = str(args.get("arg2", args.get("arg0", "")))
            add("process_open", process_target[:PYTHON_RENPY_MAX_CONSTANT_TEXT])
        if base in {"readprocessmemory", "minidumpwritedump"}:
            add("memory_read", target)
        if base == "writeprocessmemory":
            add("memory_write", target)
        if base in {"virtualallocex", "virtualalloc"}:
            add("memory_allocate", target)
        if base in {"virtualprotectex", "virtualprotect"}:
            add("memory_protect", target)
        if base in {"createremotethread", "createthread"}:
            add("thread_execute", target)
        if base == "queueuserapc":
            add("apc_execute", target)
        if base in {"setthreadcontext", "resumethread"}:
            add("context_execute", target)
        if "cryptunprotectdata" in lower or (
            base == "decrypt" and lower.startswith(("cryptography.", "win32crypt."))
        ):
            add("decrypt", target)
        if lower in {"base64.b64decode", "base64.urlsafe_b64decode", "base64.decodebytes"}:
            add("decode", target)
        if lower in {"zlib.decompress", "gzip.decompress", "bz2.decompress", "lzma.decompress"}:
            add("decompress", target)
        if lower in {"json.dumps", "pickle.dumps", "marshal.dumps", "orjson.dumps"}:
            add("serialize", target)
        if lower in {"zipfile.zipfile", "tarfile.open", "shutil.make_archive"}:
            add("archive", target)
        if lower in {
            "requests.get",
            "urllib.request.urlopen",
            "httpx.get",
            "socket.create_connection",
            "asyncio.open_connection",
        }:
            add("network_connect", target)
            urlopen_has_payload = (
                lower == "urllib.request.urlopen"
                and (positional_count >= 2 or "data" in keyword_names)
            )
            if urlopen_has_payload:
                add("network_send", target, {"request_body_present": True})
                add("network_upload", target, {"request_body_present": True})
            elif lower in {"requests.get", "urllib.request.urlopen", "httpx.get"}:
                add("network_download", target)
        if lower in {"requests.post", "requests.put", "httpx.post", "httpx.put"} or (
            base in {"send", "sendall", "sendto"} and "network_connect" in receiver_kinds
        ):
            add("network_send", target)
            if lower in {"requests.post", "requests.put", "httpx.post", "httpx.put"}:
                add("network_upload", target)
        if lower.startswith("winreg."):
            add("registry_access", target)
        return out

    @staticmethod
    def _credential_path(value: str) -> str:
        lower = value.lower().replace("\\", "/")
        if "login data" in lower:
            return "browser_login_data"
        if "local state" in lower:
            return "browser_local_state"
        if "cookies" in lower and ("chrome" in lower or "chromium" in lower or "browser" in lower):
            return "browser_cookie_store"
        return ""

    def _expression_state(self, expression: ast.AST, env: dict[str, _ValueState], function_key: str) -> _ValueState | None:
        if isinstance(expression, ast.Name):
            return env.get(expression.id)
        resolved = self._constant(expression, env, function_key)
        if resolved is None:
            return None
        return _ValueState(
            _identity("val_", self.snapshot.content_sha256, function_key, getattr(expression, "lineno", 0), repr(resolved)),
            resolved,
            (),
        )

    def _constant(
        self,
        node: ast.AST,
        env: dict[str, _ValueState],
        function_key: str,
    ) -> object:
        if isinstance(node, ast.Constant):
            if type(node.value) in (str, int, bool) or node.value is None:
                if type(node.value) is str and len(node.value) > PYTHON_RENPY_MAX_CONSTANT_TEXT:
                    return node.value[:PYTHON_RENPY_MAX_CONSTANT_TEXT]
                return node.value
            return None
        if isinstance(node, ast.Name):
            state = env.get(node.id)
            return None if state is None else state.resolved
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
            left = self._constant(node.left, env, function_key)
            right = self._constant(node.right, env, function_key)
            if isinstance(left, str) and isinstance(right, str):
                separator = "/" if isinstance(node.op, ast.Div) else ""
                return (left.rstrip("/\\") + separator + right.lstrip("/\\"))[:PYTHON_RENPY_MAX_CONSTANT_TEXT]
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for item in node.values:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    parts.append(item.value)
                elif isinstance(item, ast.FormattedValue):
                    value = self._constant(item.value, env, function_key)
                    if value is None:
                        return None
                    parts.append(str(value))
                else:
                    return None
            return "".join(parts)[:PYTHON_RENPY_MAX_CONSTANT_TEXT]
        if isinstance(node, (ast.List, ast.Tuple)):
            values = [self._constant(item, env, function_key) for item in node.elts]
            return values if all(value is not None for value in values) else None
        if isinstance(node, ast.Dict):
            output: dict[str, object] = {}
            for key_node, value_node in zip(node.keys, node.values):
                key = self._constant(key_node, env, function_key) if key_node is not None else None
                value = self._constant(value_node, env, function_key)
                if not isinstance(key, str) or value is None:
                    return None
                output[key[:256]] = value
            return output
        if isinstance(node, ast.Call):
            call = self._call_name(node.func, function_key, env)
            values = [self._constant(item, env, function_key) for item in node.args]
            if call in {"os.path.join", "posixpath.join", "ntpath.join"} and values and all(isinstance(value, str) for value in values):
                return "/".join(str(value).strip("/\\") for value in values)[:PYTHON_RENPY_MAX_CONSTANT_TEXT]
            if call in {"pathlib.Path", "Path"} and values and isinstance(values[0], str):
                return values[0]
        return None

    def _register_import_alias(self, scope: str, bound: str, target: str) -> None:
        aliases = self.import_aliases_by_function.setdefault(scope, {})
        ambiguous = self.ambiguous_import_aliases_by_function.setdefault(scope, set())
        if bound in ambiguous:
            return
        existing = aliases.get(bound)
        if existing is not None and existing != target:
            aliases.pop(bound, None)
            ambiguous.add(bound)
            self.unresolved.add("ambiguous_import_alias:" + bound[:200])
            self.limitations.add("ambiguous_import_alias")
            return
        aliases[bound] = target

    def _scope_chain(self, function_key: str) -> Iterable[str]:
        current = function_key
        visited: set[str] = set()
        while current not in visited:
            visited.add(current)
            yield current
            if current == self.module_key:
                return
            info = self.functions.get(current)
            current = self.module_key if info is None else info.parent_key

    def _resolve_call_target(
        self,
        node: ast.AST,
        function_key: str,
        env: dict[str, _ValueState] | None = None,
    ) -> _CallTarget:
        if isinstance(node, ast.Name):
            name = node.id
            if env is not None and name in env:
                return _CallTarget("local_value", "__local_value__." + name)
            for scope in self._scope_chain(function_key):
                candidates = tuple(
                    self.function_bindings_by_scope.get(scope, {}).get(name, ())
                )
                has_non_import = name in self.non_import_bindings_by_scope.get(scope, set())
                alias = self.import_aliases_by_function.get(scope, {}).get(name)
                ambiguous_import = name in self.ambiguous_import_aliases_by_function.get(scope, set())
                if candidates:
                    if len(candidates) == 1 and not has_non_import and alias is None and not ambiguous_import:
                        return _CallTarget(
                            "local_function",
                            local_function_key=candidates[0],
                        )
                    return _CallTarget("unknown")
                if has_non_import:
                    return _CallTarget("local_value", "__local_value__." + name)
                if ambiguous_import:
                    return _CallTarget("unknown")
                if alias is not None:
                    return _CallTarget("import", alias)
            if name in _BUILTIN_CALLS:
                return _CallTarget("builtin", name)
            return _CallTarget("unknown")
        if isinstance(node, ast.Attribute):
            parent = self._resolve_call_target(node.value, function_key, env)
            if parent.kind == "import":
                return _CallTarget(
                    "import",
                    (parent.canonical_name + "." + node.attr).strip("."),
                )
            if parent.kind in {"local_value", "receiver"}:
                return _CallTarget("receiver", "__receiver__." + node.attr)
            return _CallTarget("unknown")
        return _CallTarget("unknown")

    def _call_name(
        self,
        node: ast.AST,
        function_key: str,
        env: dict[str, _ValueState] | None = None,
    ) -> str:
        target = self._resolve_call_target(node, function_key, env)
        if target.kind in {"import", "builtin", "receiver", "local_value"}:
            return target.canonical_name
        return ""

    @staticmethod
    def _target_names(target: ast.AST | None) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [item.id for item in target.elts if isinstance(item, ast.Name)]
        return []

    @staticmethod
    def _assignment_names(statement: ast.stmt) -> list[str]:
        targets: list[ast.AST]
        if isinstance(statement, ast.Assign):
            targets = list(statement.targets)
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
        elif isinstance(statement, ast.AugAssign):
            targets = [statement.target]
        else:
            return []
        output: list[str] = []
        for target in targets:
            output.extend(_Analyzer._target_names(target))
        return output

    @staticmethod
    def _json_value(value: object) -> object:
        if value is None or type(value) in (str, int, bool):
            return value
        if type(value) is list:
            return [item if type(item) in (str, int, bool) or item is None else str(item) for item in value[:128]]
        if type(value) is dict:
            return {str(key)[:256]: item if type(item) in (str, int, bool) or item is None else str(item) for key, item in list(value.items())[:128]}
        return str(value)[:PYTHON_RENPY_MAX_CONSTANT_TEXT]

    def _append_operation(self, draft: _OperationDraft) -> int | None:
        if len(self.operation_drafts) >= PYTHON_RENPY_MAX_OPERATIONS:
            self.limitations.add("operation_limit_exceeded")
            return None
        self.operation_drafts.append(draft)
        return len(self.operation_drafts) - 1

    def _append_edge(self, draft: _EdgeDraft) -> None:
        if len(self.edge_drafts) >= PYTHON_RENPY_MAX_FLOW_EDGES:
            self.limitations.add("flow_edge_limit_exceeded")
            return
        self.edge_drafts.append(draft)

    def _next_ordinal(self) -> int:
        value = self._ordinal
        self._ordinal += 1
        return value

    def _finalize(self) -> StaticProgramAnalysis:
        function_ids = {
            self.module_key: _identity("fn_", self.snapshot.content_sha256, self.module_key),
            **{key: _identity("fn_", self.snapshot.content_sha256, key) for key in self.functions},
        }
        actor_ids = {key: _identity("spe_", self.snapshot.content_sha256, key) for key in function_ids}
        for draft in self.operation_drafts:
            location = StaticSourceLocation(
                locator=self.locator,
                line=getattr(draft.node, "lineno", None),
                column=getattr(draft.node, "col_offset", None),
                end_line=getattr(draft.node, "end_lineno", None),
                end_column=getattr(draft.node, "end_col_offset", None),
            )
            draft.operation = StaticOperation.create(
                language=self.language,
                operation_kind=draft.kind,
                source_location=location,
                enclosing_function_id=function_ids[draft.function_key],
                basic_block_id=_identity("bb_", self.snapshot.content_sha256, draft.function_key, draft.block_key),
                control_flow_ordinal=draft.ordinal,
                control_flow_provenance=draft.provenance,
                reachability_state=draft.reachability,
                platform=draft.platform,
                actor_program_entity=actor_ids[draft.function_key],
                target_resource_identity=draft.target_resource,
                input_value_ids=draft.input_values,
                output_value_ids=draft.output_values,
                flow_identity=draft.flow_identity,
                resolved_arguments=draft.resolved_arguments,
                resolution_state=draft.resolution,
                limitations=draft.limitations,
                integrity_status=draft.integrity,
            )
        edges: list[StaticFlowEdge] = []
        for draft in self.edge_drafts:
            source_operation = self.operation_drafts[draft.source_draft].operation if draft.source_draft is not None and draft.source_draft < len(self.operation_drafts) else None
            target_operation = self.operation_drafts[draft.target_draft].operation if draft.target_draft is not None and draft.target_draft < len(self.operation_drafts) else None
            edges.append(StaticFlowEdge.create(
                flow_identity=draft.flow_identity,
                edge_kind=draft.kind,
                source_value_id=draft.source_value_id,
                target_value_id=draft.target_value_id,
                source_operation_id="" if source_operation is None else source_operation.operation_id,
                target_operation_id="" if target_operation is None else target_operation.operation_id,
                resolution_state=draft.resolution,
                limitations=draft.limitations,
                integrity_status=draft.integrity,
            ))
        operations = tuple(draft.operation for draft in self.operation_drafts if draft.operation is not None)
        entrypoints = [function_ids[self.module_key]]
        entrypoints.extend(function_ids[key] for key, info in self.functions.items() if info.reachability == "entrypoint_reachable")
        limited = bool(self.limitations)
        return StaticProgramAnalysis(
            content_sha256=self.snapshot.content_sha256,
            content_size=self.snapshot.size,
            artifact_identity=static_artifact_identity(self.snapshot.content_sha256),
            language=self.language,
            language_version=str(sys.version_info.major) + "." + str(sys.version_info.minor),
            parser_status="partial" if limited or self.unresolved else "complete",
            parser_schema_version=PYTHON_RENPY_FRONTEND_SCHEMA_VERSION,
            parser_digest=PYTHON_RENPY_FRONTEND_DIGEST,
            operations=operations,
            flow_edges=tuple(edges),
            entrypoint_function_ids=tuple(entrypoints),
            unresolved_constructs=tuple(sorted(self.unresolved))[:PYTHON_RENPY_MAX_UNRESOLVED],
            limitations=tuple(sorted(self.limitations)),
            integrity_status="partial" if limited or self.unresolved else "verified",
        )


def _decode_python_source(raw: bytes) -> str:
    encoding, _ = tokenize.detect_encoding(BytesIO(raw).readline)
    return raw.decode(encoding, errors="strict")


def _renpy_python_source(source: str) -> str:
    """Return Python-only Ren'Py source while preserving original line numbers."""
    lines = source.splitlines()
    output = [""] * len(lines)
    in_block = False
    block_indent = 0
    for index, line in enumerate(lines):
        stripped = line.lstrip(" \t")
        indent = len(line) - len(stripped)
        header = stripped.startswith("python:") or stripped.startswith("init python:") or stripped.startswith("init python ") and stripped.endswith(":")
        if header:
            in_block = True
            block_indent = indent
            output[index] = "pass"
            continue
        if in_block:
            if stripped and indent <= block_indent:
                in_block = False
            else:
                remove = min(len(line), block_indent + 4)
                output[index] = line[remove:] if stripped else ""
                continue
        if stripped.startswith("$"):
            expression = stripped[1:].lstrip()
            output[index] = (" " * indent) + expression
    return "\n".join(output) + ("\n" if source.endswith("\n") else "")


def _unavailable(snapshot: ArtifactReadSnapshot, language: str, reason: str, *, status: str = "unavailable") -> StaticProgramAnalysis:
    return StaticProgramAnalysis(
        content_sha256=snapshot.content_sha256,
        content_size=snapshot.size,
        artifact_identity=static_artifact_identity(snapshot.content_sha256),
        language=language,
        language_version="",
        parser_status=status,
        parser_schema_version="",
        parser_digest="",
        operations=(),
        flow_edges=(),
        entrypoint_function_ids=(),
        unresolved_constructs=(),
        limitations=(),
        integrity_status="unavailable",
        unavailable_reason=reason,
    )


def analyze_python_renpy_snapshot(snapshot: object) -> PythonRenpyAnalysisResult:
    """Analyze one exact artifact snapshot, using only the canonical SQLite cache."""
    owned = require_artifact_read_snapshot(snapshot)
    extension = owned.extension.lower()
    if extension not in {".py", ".pyw", ".rpy"}:
        raise ValueError("python_renpy_frontend_extension_not_applicable")
    language = "renpy" if extension == ".rpy" else "python"
    if not owned.complete:
        return PythonRenpyAnalysisResult(_unavailable(owned, language, owned.unavailable_reason or "artifact_read_unavailable"), "computed")
    dependency = python_renpy_analysis_dependency_digest()
    hit = scan_cache_repository().get_static_analysis(
        content_sha256=owned.content_sha256,
        analysis_dependency_digest=dependency,
    )
    if hit is not None:
        return PythonRenpyAnalysisResult(hit.analysis, "sqlite_cache")
    if owned.size > PYTHON_RENPY_MAX_SOURCE_BYTES or owned.prefix_truncated:
        analysis = StaticProgramAnalysis(
            content_sha256=owned.content_sha256,
            content_size=owned.size,
            artifact_identity=static_artifact_identity(owned.content_sha256),
            language=language,
            language_version=str(sys.version_info.major) + "." + str(sys.version_info.minor),
            parser_status="truncated",
            parser_schema_version=PYTHON_RENPY_FRONTEND_SCHEMA_VERSION,
            parser_digest=PYTHON_RENPY_FRONTEND_DIGEST,
            operations=(),
            flow_edges=(),
            entrypoint_function_ids=(),
            unresolved_constructs=(),
            limitations=("source_size_limit_exceeded",),
            integrity_status="partial",
        )
    else:
        raw = owned.read_prefix(owned.size)
        try:
            source = _decode_python_source(raw)
            if language == "renpy":
                source = _renpy_python_source(source)
            tree = ast.parse(source, filename=owned.canonical_path, type_comments=True)
            node_count = 0
            stack = [tree]
            while stack:
                node_count += 1
                if node_count > PYTHON_RENPY_MAX_AST_NODES:
                    raise OverflowError("ast_node_limit_exceeded")
                stack.extend(ast.iter_child_nodes(stack.pop()))
            analysis = _Analyzer(snapshot=owned, language=language, source=source).analyze(tree)
        except (SyntaxError, IndentationError, UnicodeDecodeError, LookupError, tokenize.TokenError) as exc:
            analysis = _unavailable(owned, language, "parser_failed:" + type(exc).__name__, status="failed")
        except OverflowError:
            analysis = StaticProgramAnalysis(
                content_sha256=owned.content_sha256,
                content_size=owned.size,
                artifact_identity=static_artifact_identity(owned.content_sha256),
                language=language,
                language_version=str(sys.version_info.major) + "." + str(sys.version_info.minor),
                parser_status="truncated",
                parser_schema_version=PYTHON_RENPY_FRONTEND_SCHEMA_VERSION,
                parser_digest=PYTHON_RENPY_FRONTEND_DIGEST,
                operations=(),
                flow_edges=(),
                entrypoint_function_ids=(),
                unresolved_constructs=(),
                limitations=("ast_node_limit_exceeded",),
                integrity_status="partial",
            )
    scan_cache_repository().put_static_analysis(
        content_sha256=owned.content_sha256,
        content_size=owned.size,
        analysis_dependency_digest=dependency,
        analysis=analysis,
    )
    return PythonRenpyAnalysisResult(analysis, "computed")


__all__ = (
    "PYTHON_RENPY_FRONTEND_DIGEST",
    "PYTHON_RENPY_FRONTEND_SCHEMA_VERSION",
    "PYTHON_RENPY_MAX_SOURCE_BYTES",
    "PythonRenpyAnalysisResult",
    "analyze_python_renpy_snapshot",
    "python_renpy_analysis_dependency_digest",
)
