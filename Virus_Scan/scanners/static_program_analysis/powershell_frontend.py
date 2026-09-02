"""Bounded canonical PowerShell static-program-analysis frontend.

The frontend parses source structure and emits only language-neutral physical
operations and bounded value-flow relations. It never starts PowerShell,
loads modules or profiles, resolves remote state, or maps ATT&CK techniques.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

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
from Virus_Scan.scanners.static_program_analysis.powershell_syntax import (
    POWERSHELL_MAX_NESTING,
    POWERSHELL_MAX_STATEMENTS,
    POWERSHELL_MAX_TOKENS,
    PowerShellAssignment,
    PowerShellCommand,
    PowerShellFunction,
    PowerShellIf,
    PowerShellScript,
    PowerShellSyntaxError,
    PowerShellToken,
    parse_powershell,
)
from Virus_Scan.storage import scan_cache_repository

POWERSHELL_FRONTEND_SCHEMA_VERSION = "powershell_static_frontend_v3"
POWERSHELL_MAX_SOURCE_BYTES = 1_500_000
POWERSHELL_MAX_OPERATIONS = 4_096
POWERSHELL_MAX_FLOW_EDGES = 4_096
POWERSHELL_MAX_FUNCTIONS = 2_048
POWERSHELL_MAX_UNRESOLVED = 256
POWERSHELL_MAX_CONSTANT_TEXT = 4_096

_DYNAMIC_COMMANDS = frozenset({
    "add-type",
    "iex",
    "invoke-expression",
    "new-module",
    "scriptblock.create",
})
_SOURCE_KINDS = frozenset({
    "credential_store_query",
    "database_query",
    "file_read",
    "network_download",
})
_TRANSFORM_KINDS = frozenset({"decode", "decrypt", "decompress", "serialize"})
_SINK_KINDS = frozenset({
    "archive",
    "decode",
    "decrypt",
    "file_write",
    "network_send",
    "network_upload",
    "process_launch",
    "serialize",
})
_SECURITY_PROCESS_TARGETS = frozenset({
    "csfalconservice",
    "msmpeng",
    "securityhealthservice",
    "sense",
    "sysmon",
    "sysmon64",
})
_SECURITY_SERVICE_TARGETS = frozenset({
    "csagent",
    "sense",
    "securityhealthservice",
    "sysmon",
    "windefend",
})


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    return hashlib.sha256(encoded).hexdigest()


POWERSHELL_FRONTEND_DIGEST = _canonical_digest({
    "frontend_schema": POWERSHELL_FRONTEND_SCHEMA_VERSION,
    "ir_schema": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    "ir_schema_digest": STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    "limits": {
        "flow_edges": POWERSHELL_MAX_FLOW_EDGES,
        "functions": POWERSHELL_MAX_FUNCTIONS,
        "nesting": POWERSHELL_MAX_NESTING,
        "operations": POWERSHELL_MAX_OPERATIONS,
        "source_bytes": POWERSHELL_MAX_SOURCE_BYTES,
        "statements": POWERSHELL_MAX_STATEMENTS,
        "tokens": POWERSHELL_MAX_TOKENS,
    },
    "syntax_owner": "bounded_powershell_structure_v2",
})


def powershell_analysis_dependency_digest() -> str:
    return POWERSHELL_FRONTEND_DIGEST


def _identity(prefix: str, *parts: object) -> str:
    return prefix + _canonical_digest([str(part) for part in parts])[:40]


def _variable_name(value: str) -> str:
    text = value.strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1]
    elif text.startswith("$"):
        text = text[1:]
    return text.casefold()


def _bounded_text(value: object) -> str:
    return str(value)[:POWERSHELL_MAX_CONSTANT_TEXT]


@dataclass(frozen=True, slots=True)
class PowerShellAnalysisResult:
    analysis: StaticProgramAnalysis
    cache_source: str


@dataclass(slots=True)
class _ValueState:
    value_id: str
    resolved: object = None
    flow_identity: str = ""
    source_operation_draft: int | None = None


@dataclass(slots=True)
class _OperationDraft:
    kind: str
    token: PowerShellToken
    function_key: str
    block_key: str
    ordinal: int
    reachability: str
    platform: str
    target_resource: str
    input_values: tuple[str, ...]
    output_values: tuple[str, ...]
    flow_identity: str
    resolved_arguments: dict[str, object]
    resolution: str
    limitations: tuple[str, ...]
    integrity: str
    operation: StaticOperation | None = None


@dataclass(slots=True)
class _EdgeDraft:
    kind: str
    flow_identity: str
    source_value_id: str
    target_value_id: str
    source_draft: int | None
    target_draft: int | None
    resolution: str = "resolved"
    limitations: tuple[str, ...] = ()
    integrity: str = "verified"


class _Analyzer:
    def __init__(self, *, snapshot: ArtifactReadSnapshot, script: PowerShellScript) -> None:
        self.snapshot = snapshot
        self.script = script
        self.module_key = "<script>"
        self.functions: dict[str, PowerShellFunction] = {}
        self.ambiguous_functions: set[str] = set()
        self.function_reachability: dict[str, str] = {}
        self.operations: list[_OperationDraft] = []
        self.edges: list[_EdgeDraft] = []
        self.unresolved: set[str] = set()
        self.limitations: set[str] = set()
        self.ordinal = 0

    def analyze(self) -> StaticProgramAnalysis:
        self._collect_functions(self.script.statements)
        self._resolve_function_reachability()
        module_env: dict[str, _ValueState] = {}
        module_statements = tuple(
            statement for statement in self.script.statements
            if type(statement) is not PowerShellFunction
        )
        self._visit_block(
            module_statements,
            function_key=self.module_key,
            block_key="script_entry",
            reachability="entrypoint_reachable",
            env=module_env,
        )
        for name in sorted(self.functions):
            function = self.functions[name]
            self._visit_block(
                function.body,
                function_key=name,
                block_key="function_entry",
                reachability=self.function_reachability.get(name, "locally_reachable"),
                env={},
            )
        return self._finalize()

    def _collect_functions(self, statements: tuple[object, ...]) -> None:
        for statement in statements:
            if type(statement) is PowerShellFunction:
                name = statement.name.value.casefold()
                if name in self.ambiguous_functions:
                    continue
                if name in self.functions:
                    self.functions.pop(name, None)
                    self.ambiguous_functions.add(name)
                    self._remember_unresolved("duplicate_function:" + name[:200])
                    self.limitations.add("duplicate_function_name")
                    continue
                if len(self.functions) >= POWERSHELL_MAX_FUNCTIONS:
                    self.limitations.add("function_limit_exceeded")
                    continue
                self.functions[name] = statement
                self._collect_functions(statement.body)
            elif type(statement) is PowerShellIf:
                self._collect_functions(statement.then_body)
                self._collect_functions(statement.else_body)

    def _resolve_function_reachability(self) -> None:
        calls: dict[str, set[str]] = {self.module_key: set()}
        for name, function in self.functions.items():
            calls[name] = self._function_calls(function.body)
        calls[self.module_key] = self._function_calls(self.script.statements, skip_functions=True)
        reachable = set(calls[self.module_key]) & set(self.functions)
        queue = list(sorted(reachable))
        while queue:
            current = queue.pop(0)
            for called in sorted(calls.get(current, set())):
                if called in self.functions and called not in reachable:
                    reachable.add(called)
                    queue.append(called)
        self.function_reachability = {
            name: "entrypoint_reachable" if name in reachable else "locally_reachable"
            for name in self.functions
        }

    def _function_calls(self, statements: tuple[object, ...], *, skip_functions: bool = False) -> set[str]:
        calls: set[str] = set()
        for statement in statements:
            if type(statement) is PowerShellCommand:
                for segment in self._pipeline_segments(statement.tokens):
                    name = self._command_name(segment)
                    if name:
                        calls.add(name)
            elif type(statement) is PowerShellAssignment:
                for segment in self._pipeline_segments(statement.expression):
                    name = self._command_name(segment)
                    if name:
                        calls.add(name)
            elif type(statement) is PowerShellIf:
                calls.update(self._function_calls(statement.then_body))
                calls.update(self._function_calls(statement.else_body))
            elif type(statement) is PowerShellFunction and not skip_functions:
                calls.update(self._function_calls(statement.body))
        return calls

    def _visit_block(
        self,
        statements: tuple[object, ...],
        *,
        function_key: str,
        block_key: str,
        reachability: str,
        env: dict[str, _ValueState],
    ) -> None:
        current_reachability = reachability
        for index, statement in enumerate(statements):
            statement_block = block_key + ":" + str(index)
            if type(statement) is PowerShellAssignment:
                self._visit_assignment(
                    statement,
                    function_key=function_key,
                    block_key=statement_block,
                    reachability=current_reachability,
                    env=env,
                )
            elif type(statement) is PowerShellCommand:
                state, terminal = self._visit_command(
                    statement.tokens,
                    function_key=function_key,
                    block_key=statement_block,
                    reachability=current_reachability,
                    env=env,
                )
                del state
                if terminal:
                    current_reachability = "unreachable"
            elif type(statement) is PowerShellIf:
                truth = self._condition_truth(statement.condition, env)
                if truth is True:
                    then_reachability, else_reachability = current_reachability, "unreachable"
                elif truth is False:
                    then_reachability, else_reachability = "unreachable", current_reachability
                else:
                    conditional = "unreachable" if current_reachability == "unreachable" else "conditionally_reachable"
                    then_reachability = conditional
                    else_reachability = conditional
                self._visit_block(
                    statement.then_body,
                    function_key=function_key,
                    block_key=statement_block + ":then",
                    reachability=then_reachability,
                    env=dict(env),
                )
                self._visit_block(
                    statement.else_body,
                    function_key=function_key,
                    block_key=statement_block + ":else",
                    reachability=else_reachability,
                    env=dict(env),
                )
            elif type(statement) is PowerShellFunction:
                continue

    def _visit_assignment(
        self,
        statement: PowerShellAssignment,
        *,
        function_key: str,
        block_key: str,
        reachability: str,
        env: dict[str, _ValueState],
    ) -> None:
        variable = _variable_name(statement.variable.value)
        if not variable:
            self._remember_unresolved("assignment_variable_unresolved")
            return
        if self._looks_like_command(statement.expression):
            state, _ = self._visit_command(
                statement.expression,
                function_key=function_key,
                block_key=block_key + ":rhs",
                reachability=reachability,
                env=env,
            )
            if state is not None:
                env[variable] = state
                return
        resolved, states = self._resolve_expression(statement.expression, env)
        value_id = _identity(
            "val_",
            self.snapshot.content_sha256,
            function_key,
            statement.variable.line,
            statement.variable.column,
            variable,
        )
        if states:
            source = states[0]
            env[variable] = _ValueState(
                value_id=value_id,
                resolved=resolved,
                flow_identity=source.flow_identity,
                source_operation_draft=source.source_operation_draft,
            )
            if source.flow_identity:
                self._append_edge(_EdgeDraft(
                    "assignment",
                    source.flow_identity,
                    source.value_id,
                    value_id,
                    source.source_operation_draft,
                    None,
                ))
        else:
            env[variable] = _ValueState(value_id=value_id, resolved=resolved)

    def _visit_command(
        self,
        tokens: tuple[PowerShellToken, ...],
        *,
        function_key: str,
        block_key: str,
        reachability: str,
        env: dict[str, _ValueState],
    ) -> tuple[_ValueState | None, bool]:
        previous: _ValueState | None = None
        terminal = False
        for pipeline_index, segment in enumerate(self._pipeline_segments(tokens)):
            if not segment:
                continue
            command_name = self._command_name(segment)
            if command_name in self.ambiguous_functions:
                self._remember_unresolved("ambiguous_function_call:" + command_name[:200])
                previous = None
                continue
            if command_name in self.functions:
                previous = None
                continue
            if command_name in {"return", "exit", "throw", "break", "continue"}:
                terminal = True
                previous = None
                continue
            if self._dynamic_command(segment, command_name):
                self._remember_unresolved("dynamic_command:" + (command_name or "call_operator")[:200])
                previous = None
                continue
            arguments = self._arguments(self._command_argument_tokens(segment), env)
            input_states = list(arguments["states"])
            if previous is not None:
                input_states.insert(0, previous)
            specs = self._operation_specs(command_name, segment, arguments)
            if not specs:
                previous = None
                continue
            common_flow, ambiguous_flow = self._common_flow(input_states)
            output_id = _identity(
                "val_",
                self.snapshot.content_sha256,
                function_key,
                segment[0].line,
                segment[0].column,
                pipeline_index,
                command_name,
            )
            produced_state: _ValueState | None = None
            for kind, target, extra in specs:
                is_source = kind in _SOURCE_KINDS or extra.get("_value_source") is True
                is_transform = kind in _TRANSFORM_KINDS
                output_values = (output_id,) if is_source or is_transform else ()
                flow = common_flow if kind in _SINK_KINDS or is_transform else ""
                if is_source and not flow:
                    flow = _identity(
                        "flow_",
                        self.snapshot.content_sha256,
                        function_key,
                        segment[0].line,
                        kind,
                        target,
                    )
                target_identity = _identity("res_", target) if target else ""
                limitations: list[str] = []
                target_resolved = bool(extra.get("_target_resolved", bool(target)))
                input_resolved = bool(extra.get("_input_resolved", True))
                if (not target or not target_resolved) and self._target_required(kind):
                    limitations.append("target_unresolved")
                if not input_resolved:
                    limitations.append("argument_unresolved")
                if ambiguous_flow and kind in _SINK_KINDS:
                    limitations.append("ambiguous_source_flow")
                resolution = "resolved" if not limitations else "partial"
                integrity = "verified" if not limitations else "partial"
                draft_index = self._append_operation(_OperationDraft(
                    kind=kind,
                    token=segment[0],
                    function_key=function_key,
                    block_key=block_key + ":pipe:" + str(pipeline_index),
                    ordinal=self._next_ordinal(),
                    reachability=reachability,
                    platform=self._platform(command_name, kind),
                    target_resource=target_identity,
                    input_values=tuple(state.value_id for state in input_states),
                    output_values=output_values,
                    flow_identity=flow,
                    resolved_arguments={
                        "call_name": command_name,
                        "named_parameters": arguments["named"],
                        "positional_arguments": arguments["positional"],
                        **{key: value for key, value in extra.items() if not key.startswith("_")},
                    },
                    resolution=resolution,
                    limitations=tuple(limitations),
                    integrity=integrity,
                ))
                if draft_index is None:
                    continue
                if kind in _SINK_KINDS and not ambiguous_flow:
                    for state in input_states:
                        if state.flow_identity:
                            self._append_edge(_EdgeDraft(
                                "source_to_sink",
                                state.flow_identity,
                                state.value_id,
                                state.value_id,
                                state.source_operation_draft,
                                draft_index,
                            ))
                if is_source or is_transform:
                    source_draft = draft_index
                    if is_transform:
                        source_drafts = {
                            state.source_operation_draft
                            for state in input_states
                            if state.flow_identity and state.source_operation_draft is not None
                        }
                        if len(source_drafts) == 1:
                            source_draft = next(iter(source_drafts))
                    produced_state = _ValueState(
                        value_id=output_id,
                        resolved=None,
                        flow_identity=flow,
                        source_operation_draft=source_draft,
                    )
            previous = produced_state
        return previous, terminal

    @staticmethod
    def _pipeline_segments(tokens: tuple[PowerShellToken, ...]) -> tuple[tuple[PowerShellToken, ...], ...]:
        segments: list[list[PowerShellToken]] = [[]]
        depth = 0
        for token in tokens:
            if token.kind == "symbol" and token.value in {"(", "["}:
                depth += 1
            elif token.kind == "symbol" and token.value in {")", "]"}:
                depth = max(0, depth - 1)
            if token.kind == "symbol" and token.value == "|" and depth == 0:
                segments.append([])
            else:
                segments[-1].append(token)
        return tuple(tuple(segment) for segment in segments)

    @staticmethod
    def _command_name(tokens: tuple[PowerShellToken, ...]) -> str:
        if not tokens or tokens[0].kind == "string":
            return ""
        if tokens[0].value in {"&", "."}:
            return ""
        if tokens[0].kind == "symbol" and tokens[0].value == "[":
            parts: list[str] = []
            for token in tokens:
                if token.kind == "symbol" and token.value == "(":
                    break
                parts.append(token.value)
            return "".join(parts).casefold()
        value = tokens[0].value.casefold()
        return value.rsplit("\\", 1)[-1]

    @staticmethod
    def _command_argument_tokens(tokens: tuple[PowerShellToken, ...]) -> tuple[PowerShellToken, ...]:
        if tokens and tokens[0].kind == "symbol" and tokens[0].value == "[":
            for index, token in enumerate(tokens):
                if token.kind == "symbol" and token.value == "(":
                    tail = tokens[index + 1:]
                    if tail and tail[-1].kind == "symbol" and tail[-1].value == ")":
                        tail = tail[:-1]
                    return tail
            return ()
        return tokens[1:] if tokens else ()

    def _arguments(
        self,
        tokens: tuple[PowerShellToken, ...],
        env: dict[str, _ValueState],
    ) -> dict[str, object]:
        named: dict[str, object] = {}
        positional: list[object] = []
        states: list[_ValueState] = []
        unresolved_named: set[str] = set()
        unresolved_positions: set[int] = set()
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token.kind == "word" and token.value.startswith("-") and len(token.value) > 1:
                raw_name = token.value[1:]
                inline_value: str | None = None
                if ":" in raw_name:
                    raw_name, inline_value = raw_name.split(":", 1)
                name = raw_name.casefold()
                if inline_value:
                    named[name] = inline_value[:POWERSHELL_MAX_CONSTANT_TEXT]
                    index += 1
                    continue
                if index + 1 < len(tokens) and not (
                    tokens[index + 1].kind == "word" and tokens[index + 1].value.startswith("-")
                ):
                    value, found = self._resolve_expression((tokens[index + 1],), env)
                    if value is None and not found:
                        unresolved_named.add(name)
                    named[name] = value if value is not None else tokens[index + 1].value[:POWERSHELL_MAX_CONSTANT_TEXT]
                    states.extend(found)
                    index += 2
                    continue
                named[name] = True
                index += 1
                continue
            value, found = self._resolve_expression((token,), env)
            position = len(positional)
            if value is None and not found and token.kind in {"variable", "symbol"}:
                unresolved_positions.add(position)
            positional.append(value if value is not None else token.value[:POWERSHELL_MAX_CONSTANT_TEXT])
            states.extend(found)
            index += 1
        unique_states: list[_ValueState] = []
        seen = set()
        for state in states:
            if state.value_id not in seen:
                seen.add(state.value_id)
                unique_states.append(state)
        return {
            "named": named,
            "positional": positional,
            "states": tuple(unique_states),
            "unresolved_named": tuple(sorted(unresolved_named)),
            "unresolved_positions": tuple(sorted(unresolved_positions)),
        }

    def _resolve_expression(
        self,
        tokens: tuple[PowerShellToken, ...],
        env: dict[str, _ValueState],
    ) -> tuple[object, tuple[_ValueState, ...]]:
        if not tokens:
            return None, ()
        states: list[_ValueState] = []
        values: list[object] = []
        unresolved = False
        for token in tokens:
            if token.kind == "variable":
                name = _variable_name(token.value)
                if name in {"true", "false", "null"}:
                    values.append({"true": True, "false": False, "null": None}[name])
                    continue
                state = env.get(name)
                if state is None:
                    unresolved = True
                    self._remember_unresolved("variable_unresolved:" + name[:200])
                else:
                    states.append(state)
                    values.append(state.resolved)
                continue
            if token.kind == "string":
                values.append(token.value[:POWERSHELL_MAX_CONSTANT_TEXT])
                if token.quote in {'"', '@"'}:
                    for name in token.interpolated_variables:
                        state = env.get(name)
                        if state is not None:
                            states.append(state)
                        else:
                            unresolved = True
                            self._remember_unresolved("variable_unresolved:" + name[:200])
                continue
            if token.kind == "number":
                values.append(int(token.value))
                continue
            if token.kind == "word" and token.value == "+":
                continue
            values.append(token.value[:POWERSHELL_MAX_CONSTANT_TEXT])
        if unresolved:
            return None, tuple(states)
        if len(tokens) == 1 and values:
            return values[0], tuple(states)
        if values and all(type(value) in {str, int, bool} or value is None for value in values):
            text = "".join("" if value is None else str(value) for value in values)
            return text[:POWERSHELL_MAX_CONSTANT_TEXT], tuple(states)
        return (None if unresolved else values), tuple(states)

    def _condition_truth(
        self,
        tokens: tuple[PowerShellToken, ...],
        env: dict[str, _ValueState],
    ) -> bool | None:
        value, _ = self._resolve_expression(tokens, env)
        if type(value) is bool:
            return value
        if value is None and len(tokens) == 1 and tokens[0].value.casefold() == "$null":
            return False
        if type(value) is int:
            return value != 0
        return None

    @staticmethod
    def _looks_like_command(tokens: tuple[PowerShellToken, ...]) -> bool:
        if not tokens:
            return False
        if any(token.kind == "symbol" and token.value == "|" for token in tokens):
            return True
        first = tokens[0]
        if first.kind == "symbol" and first.value == "[":
            return any(token.kind == "symbol" and token.value == "(" for token in tokens)
        return first.kind == "word" and first.value not in {"+", "-", "*", "/"}

    def _dynamic_command(self, tokens: tuple[PowerShellToken, ...], command_name: str) -> bool:
        if command_name in _DYNAMIC_COMMANDS:
            return True
        if tokens and tokens[0].value in {"&", "."}:
            return True
        lowered = tuple(token.value.casefold() for token in tokens)
        if any(item in {"-encodedcommand", "-enc", "-e"} for item in lowered):
            self._remember_unresolved("encoded_or_generated_code")
        return False

    def _operation_specs(
        self,
        command: str,
        tokens: tuple[PowerShellToken, ...],
        arguments: dict[str, object],
    ) -> tuple[tuple[str, str, dict[str, object]], ...]:
        named = arguments["named"]
        positional = arguments["positional"]
        unresolved_named = set(arguments["unresolved_named"])
        unresolved_positions = set(arguments["unresolved_positions"])
        assert type(named) is dict and type(positional) is list
        all_inputs_resolved = not unresolved_named and not unresolved_positions

        def argument(*names: str, position: int = 0) -> tuple[str, bool]:
            for name in names:
                if name in named:
                    value = named.get(name)
                    if value is not None and value is not True:
                        return _bounded_text(value), name not in unresolved_named
            if len(positional) > position:
                return _bounded_text(positional[position]), position not in unresolved_positions
            return "", False

        target, target_resolved = argument("literalpath", "path", "filepath", "uri", "url", "name")
        specs: list[tuple[str, str, dict[str, object]]] = []

        def add(
            kind: str,
            owned_target: str = target,
            *,
            owned_target_resolved: bool = target_resolved,
            **extra: object,
        ) -> None:
            specs.append((
                kind,
                owned_target[:POWERSHELL_MAX_CONSTANT_TEXT],
                {"_target_resolved": owned_target_resolved, **extra},
            ))

        if command in {"get-content", "gc", "type", "cat"} or "readallbytes" in command or "readalltext" in command:
            add("file_read")
            credential_family = self._credential_path(target)
            if credential_family:
                add("credential_store_discovery", target, resource_family=credential_family)
        if command in {"set-content", "sc", "out-file", "add-content", "ac"} or "writeallbytes" in command or "writealltext" in command:
            add("file_write")
        if command in {"start-process", "saps", "start", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe"}:
            process_target, process_target_resolved = argument("filepath", position=0)
            add("process_launch", process_target, owned_target_resolved=process_target_resolved)
        if command in {"invoke-webrequest", "iwr", "invoke-restmethod", "irm", "start-bitstransfer"}:
            url, url_resolved = argument("uri", "url", "source", position=0)
            add("network_connect", url, owned_target_resolved=url_resolved)
            method = str(named.get("method", "get")).casefold()
            has_body = any(name in named for name in {"body", "infile", "form"})
            body_resolved = not any(name in unresolved_named for name in {"body", "infile", "form"})
            bits_upload = command == "start-bitstransfer" and bool(named.get("upload"))
            if method in {"post", "put", "patch"} or has_body or bits_upload:
                add(
                    "network_send",
                    url,
                    owned_target_resolved=url_resolved,
                    _input_resolved=body_resolved,
                    request_body_present=True,
                )
                add(
                    "network_upload",
                    url,
                    owned_target_resolved=url_resolved,
                    _input_resolved=body_resolved,
                    request_body_present=True,
                )
            elif method in {"get", ""}:
                add("network_download", url, owned_target_resolved=url_resolved)
        if command in {"invoke-sqlcmd", "invoke-sqlitequery"}:
            server, server_resolved = argument("serverinstance", "database", position=0)
            add("database_open", server, owned_target_resolved=server_resolved)
            query, query_resolved = argument("query", position=1)
            if query:
                add(
                    "database_query",
                    server,
                    owned_target_resolved=server_resolved,
                    _input_resolved=query_resolved,
                )
                if any(term in query.casefold() for term in ("login", "password", "credential", "cookie")):
                    add(
                        "credential_store_query",
                        server,
                        owned_target_resolved=server_resolved,
                        _input_resolved=query_resolved,
                        query=query,
                    )
            credential_family = self._credential_path(server)
            if credential_family:
                add("credential_store_discovery", server, resource_family=credential_family)
        registry_target = target.casefold()
        registry_reads = {"get-itemproperty", "get-childitem", "gci", "get-item"}
        registry_writes = {"set-itemproperty", "new-itemproperty", "remove-itemproperty", "set-item", "new-item", "remove-item"}
        if command in registry_reads | registry_writes and (
            registry_target.startswith(("hklm:", "hkcu:", "hkcr:", "hku:", "hkcc:", "registry::"))
            or "registry" in command
        ):
            add("registry_access", access_mode="read" if command in registry_reads else "write", _value_source=command in registry_reads)
        if command == "compress-archive":
            add("archive", _input_resolved=all_inputs_resolved)
        if command == "expand-archive":
            add("decompress", _input_resolved=all_inputs_resolved)
        if command in {"convertto-json", "export-clixml"}:
            add("serialize", _input_resolved=all_inputs_resolved)
        if "frombase64string" in command or command in {"certutil"} and "-decode" in {token.value.casefold() for token in tokens}:
            add("decode", _input_resolved=all_inputs_resolved)
        if "protecteddata]::unprotect" in command or "cryptunprotectdata" in command:
            add("decrypt", _input_resolved=all_inputs_resolved)
        if command in {"stop-service", "spsv"}:
            service_target, service_target_resolved = argument("name", position=0)
            if service_target.casefold() in _SECURITY_SERVICE_TARGETS:
                add(
                    "security_service_stop",
                    service_target,
                    owned_target_resolved=service_target_resolved,
                )
            else:
                self._remember_unresolved("generic_service_stop:" + service_target[:200])
        if command in {"stop-process", "kill", "spps"}:
            process_target, process_target_resolved = argument("name", "id", position=0)
            if process_target.casefold().removesuffix(".exe") in _SECURITY_PROCESS_TARGETS:
                add(
                    "security_process_terminate",
                    process_target,
                    owned_target_resolved=process_target_resolved,
                )
            else:
                self._remember_unresolved("generic_process_terminate:" + process_target[:200])
        if command in {"set-mppreference", "add-mppreference", "remove-mppreference"}:
            if bool(named.get("disablerealtimemonitoring")) or bool(named.get("disablebehaviormonitoring")):
                add("security_control_disable", "windows_defender")
            else:
                add("security_configuration_modify", "windows_defender")
        object_type, object_type_resolved = argument("typename", position=0)
        if command == "new-object" and "net.sockets.tcpclient" in object_type.casefold():
            socket_target, socket_target_resolved = argument("argumentlist", position=1)
            add(
                "network_connect",
                socket_target,
                owned_target_resolved=object_type_resolved and socket_target_resolved,
            )
        return tuple(specs)

    @staticmethod
    def _platform(command: str, kind: str) -> str:
        if (
            kind.startswith("security_")
            or kind == "registry_access"
            or "protecteddata]::unprotect" in command
            or "cryptunprotectdata" in command
            or command in {"powershell", "powershell.exe"}
        ):
            return "windows"
        return ""

    @staticmethod
    def _target_required(kind: str) -> bool:
        return kind not in {"archive", "decode", "decrypt", "decompress", "serialize"}

    @staticmethod
    def _credential_path(value: str) -> str:
        lower = value.casefold().replace("\\", "/")
        if "login data" in lower:
            return "browser_login_data"
        if "local state" in lower:
            return "browser_local_state"
        if "cookies" in lower:
            return "browser_cookie_store"
        return ""

    @staticmethod
    def _common_flow(states: list[_ValueState]) -> tuple[str, bool]:
        flows = {state.flow_identity for state in states if state.flow_identity}
        return (next(iter(flows)), False) if len(flows) == 1 else ("", len(flows) > 1)

    def _append_operation(self, draft: _OperationDraft) -> int | None:
        if len(self.operations) >= POWERSHELL_MAX_OPERATIONS:
            self.limitations.add("operation_limit_exceeded")
            return None
        self.operations.append(draft)
        return len(self.operations) - 1

    def _append_edge(self, draft: _EdgeDraft) -> None:
        if len(self.edges) >= POWERSHELL_MAX_FLOW_EDGES:
            self.limitations.add("flow_edge_limit_exceeded")
            return
        self.edges.append(draft)

    def _remember_unresolved(self, value: str) -> None:
        if len(self.unresolved) >= POWERSHELL_MAX_UNRESOLVED:
            self.limitations.add("unresolved_construct_limit_exceeded")
            return
        self.unresolved.add(value[:512])

    def _next_ordinal(self) -> int:
        value = self.ordinal
        self.ordinal += 1
        return value

    def _finalize(self) -> StaticProgramAnalysis:
        function_ids = {
            self.module_key: _identity("fn_", self.snapshot.content_sha256, self.module_key),
            **{
                name: _identity("fn_", self.snapshot.content_sha256, "function", name)
                for name in self.functions
            },
        }
        actor_ids = {
            name: _identity("spe_", self.snapshot.content_sha256, name)
            for name in function_ids
        }
        for draft in self.operations:
            draft.operation = StaticOperation.create(
                language="powershell",
                operation_kind=draft.kind,
                source_location=StaticSourceLocation(
                    locator=static_artifact_identity(self.snapshot.content_sha256),
                    line=draft.token.line,
                    column=draft.token.column,
                    end_line=draft.token.end_line,
                    end_column=draft.token.end_column,
                ),
                enclosing_function_id=function_ids[draft.function_key],
                basic_block_id=_identity(
                    "bb_", self.snapshot.content_sha256, draft.function_key, draft.block_key,
                ),
                control_flow_ordinal=draft.ordinal,
                control_flow_provenance="static_control_flow",
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
        finalized_edges: list[StaticFlowEdge] = []
        for draft in self.edges:
            source = self.operations[draft.source_draft].operation if draft.source_draft is not None else None
            target = self.operations[draft.target_draft].operation if draft.target_draft is not None else None
            finalized_edges.append(StaticFlowEdge.create(
                flow_identity=draft.flow_identity,
                edge_kind=draft.kind,
                source_value_id=draft.source_value_id,
                target_value_id=draft.target_value_id,
                source_operation_id="" if source is None else source.operation_id,
                target_operation_id="" if target is None else target.operation_id,
                resolution_state=draft.resolution,
                limitations=draft.limitations,
                integrity_status=draft.integrity,
            ))
        limited = bool(self.limitations & {
            "flow_edge_limit_exceeded",
            "function_limit_exceeded",
            "operation_limit_exceeded",
            "unresolved_construct_limit_exceeded",
        })
        return StaticProgramAnalysis(
            content_sha256=self.snapshot.content_sha256,
            content_size=self.snapshot.size,
            artifact_identity=static_artifact_identity(self.snapshot.content_sha256),
            language="powershell",
            language_version="source_syntax_v1",
            parser_status="truncated" if limited else "complete",
            parser_schema_version=POWERSHELL_FRONTEND_SCHEMA_VERSION,
            parser_digest=POWERSHELL_FRONTEND_DIGEST,
            operations=tuple(draft.operation for draft in self.operations if draft.operation is not None),
            flow_edges=tuple(finalized_edges),
            entrypoint_function_ids=(function_ids[self.module_key],),
            unresolved_constructs=tuple(sorted(self.unresolved)),
            limitations=tuple(sorted(self.limitations)),
            integrity_status="partial" if limited else "verified",
        )


def _unavailable(
    snapshot: ArtifactReadSnapshot,
    reason: str,
    *,
    status: str = "unavailable",
) -> StaticProgramAnalysis:
    return StaticProgramAnalysis(
        content_sha256=snapshot.content_sha256,
        content_size=snapshot.size,
        artifact_identity=static_artifact_identity(snapshot.content_sha256),
        language="powershell",
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


def _decode_powershell_source(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", "strict")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", "strict")
    if b"\x00" in raw:
        raise UnicodeDecodeError("utf-8", raw, 0, min(1, len(raw)), "powershell_encoding_bom_required")
    return raw.decode("utf-8", "strict")


def analyze_powershell_snapshot(snapshot: object) -> PowerShellAnalysisResult:
    """Analyze one exact PowerShell artifact using the canonical SQLite cache."""
    owned = require_artifact_read_snapshot(snapshot)
    if owned.extension.lower() not in {".ps1", ".psm1"}:
        raise ValueError("powershell_frontend_extension_not_applicable")
    if not owned.complete:
        return PowerShellAnalysisResult(
            _unavailable(owned, owned.unavailable_reason or "artifact_read_unavailable"),
            "computed",
        )
    dependency = powershell_analysis_dependency_digest()
    hit = scan_cache_repository().get_static_analysis(
        content_sha256=owned.content_sha256,
        analysis_dependency_digest=dependency,
    )
    if hit is not None:
        return PowerShellAnalysisResult(hit.analysis, "sqlite_cache")
    if owned.size > POWERSHELL_MAX_SOURCE_BYTES or owned.prefix_truncated:
        analysis = StaticProgramAnalysis(
            content_sha256=owned.content_sha256,
            content_size=owned.size,
            artifact_identity=static_artifact_identity(owned.content_sha256),
            language="powershell",
            language_version="source_syntax_v1",
            parser_status="truncated",
            parser_schema_version=POWERSHELL_FRONTEND_SCHEMA_VERSION,
            parser_digest=POWERSHELL_FRONTEND_DIGEST,
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
            source = _decode_powershell_source(raw)
            script = parse_powershell(source)
            analysis = _Analyzer(snapshot=owned, script=script).analyze()
        except (UnicodeDecodeError, PowerShellSyntaxError) as exc:
            analysis = _unavailable(owned, "parser_failed:" + type(exc).__name__, status="failed")
        except OverflowError as exc:
            reason = exc.args[0] if len(exc.args) == 1 and type(exc.args[0]) is str else ""
            if reason in {
                "powershell_nesting_limit_exceeded",
                "powershell_statement_limit_exceeded",
                "powershell_token_limit_exceeded",
            }:
                analysis = StaticProgramAnalysis(
                    content_sha256=owned.content_sha256,
                    content_size=owned.size,
                    artifact_identity=static_artifact_identity(owned.content_sha256),
                    language="powershell",
                    language_version="source_syntax_v1",
                    parser_status="truncated",
                    parser_schema_version=POWERSHELL_FRONTEND_SCHEMA_VERSION,
                    parser_digest=POWERSHELL_FRONTEND_DIGEST,
                    operations=(),
                    flow_edges=(),
                    entrypoint_function_ids=(),
                    unresolved_constructs=(),
                    limitations=(reason,),
                    integrity_status="partial",
                )
            else:
                analysis = _unavailable(owned, "parser_failed:OverflowError", status="failed")
    scan_cache_repository().put_static_analysis(
        content_sha256=owned.content_sha256,
        content_size=owned.size,
        analysis_dependency_digest=dependency,
        analysis=analysis,
    )
    return PowerShellAnalysisResult(analysis, "computed")


__all__ = (
    "POWERSHELL_FRONTEND_DIGEST",
    "POWERSHELL_FRONTEND_SCHEMA_VERSION",
    "POWERSHELL_MAX_SOURCE_BYTES",
    "PowerShellAnalysisResult",
    "analyze_powershell_snapshot",
    "powershell_analysis_dependency_digest",
)
