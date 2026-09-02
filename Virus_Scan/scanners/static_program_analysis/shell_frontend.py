"""Bounded canonical POSIX-shell static-program-analysis frontend.

The frontend never invokes a shell, expands the host environment, or resolves
filesystem state.  It projects only structurally parsed commands, reachability,
redirections, and reproducible local value flows into the shared static IR.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re

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
from Virus_Scan.scanners.static_program_analysis.shell_syntax import (
    SHELL_MAX_BLOCK_DEPTH,
    SHELL_MAX_COMMANDS,
    SHELL_MAX_CONTINUATIONS,
    SHELL_MAX_FUNCTIONS,
    SHELL_MAX_LINE_LENGTH,
    SHELL_MAX_LOGICAL_LINES,
    SHELL_MAX_PHYSICAL_LINES,
    SHELL_MAX_WORDS,
    ShellCommand,
    ShellScript,
    ShellSyntaxError,
    parse_shell,
)
from Virus_Scan.storage import scan_cache_repository

SHELL_FRONTEND_SCHEMA_VERSION = "shell_static_frontend_v3"
SHELL_MAX_SOURCE_BYTES = 1_500_000
SHELL_MAX_OPERATIONS = 4_096
SHELL_MAX_FLOW_EDGES = 4_096
SHELL_MAX_UNRESOLVED = 256
SHELL_MAX_CONSTANT_TEXT = 4_096

_VARIABLE = re.compile(r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")
_ASSIGNMENT = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$", re.DOTALL)
_COMMAND_SUBSTITUTION = re.compile(r"^\$\(\s*(?P<command>cat|head|tail)\s+(?P<path>[^|;&()]+?)\s*\)$", re.IGNORECASE)
_URL = re.compile(r"^https?://", re.IGNORECASE)
_SECURITY_PROCESSES = frozenset({
    "clamd", "clamdscan", "falcon-sensor", "osqueryd", "sentinelone", "sysmon",
})
_SECURITY_SERVICES = frozenset({
    "clamav-daemon", "falcon-sensor", "osqueryd", "sentinelone", "sysmon",
})
_KNOWN_PROCESS_COMMANDS = frozenset({
    "bash", "dash", "env", "ksh", "nohup", "perl", "php", "python", "python3",
    "ruby", "sh", "ssh", "sudo", "systemctl", "service", "xargs", "zsh",
})
_SHELL_BUILTINS = frozenset({
    ":", ".", "break", "cd", "continue", "echo", "eval", "exec", "exit", "export",
    "false", "printf", "read", "readonly", "return", "set", "shift", "source", "test",
    "trap", "true", "umask", "unset", "wait",
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


SHELL_FRONTEND_DIGEST = _canonical_digest({
    "frontend_schema": SHELL_FRONTEND_SCHEMA_VERSION,
    "ir_schema": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    "ir_schema_digest": STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    "limits": {
        "block_depth": SHELL_MAX_BLOCK_DEPTH,
        "commands": SHELL_MAX_COMMANDS,
        "continuations": SHELL_MAX_CONTINUATIONS,
        "flow_edges": SHELL_MAX_FLOW_EDGES,
        "functions": SHELL_MAX_FUNCTIONS,
        "line_length": SHELL_MAX_LINE_LENGTH,
        "logical_lines": SHELL_MAX_LOGICAL_LINES,
        "operations": SHELL_MAX_OPERATIONS,
        "physical_lines": SHELL_MAX_PHYSICAL_LINES,
        "source_bytes": SHELL_MAX_SOURCE_BYTES,
        "words": SHELL_MAX_WORDS,
    },
    "syntax_owner": "bounded_posix_shell_structure_v1",
})


def shell_analysis_dependency_digest() -> str:
    return SHELL_FRONTEND_DIGEST


def _identity(prefix: str, *parts: object) -> str:
    return prefix + _canonical_digest([str(part) for part in parts])[:40]


def _bounded_text(value: object) -> str:
    return str(value)[:SHELL_MAX_CONSTANT_TEXT]


def _basename(value: str) -> str:
    text = value.strip().strip("'\"")
    return PurePosixPath(text).name.casefold() if text else ""


@dataclass(frozen=True, slots=True)
class ShellAnalysisResult:
    analysis: StaticProgramAnalysis
    cache_source: str


@dataclass(slots=True)
class _ValueState:
    value_id: str
    resolved: str = ""
    flow_identity: str = ""
    source_draft: int | None = None


@dataclass(slots=True)
class _OperationDraft:
    kind: str
    command: ShellCommand
    scope: str
    ordinal: int
    reachability: str
    target: str
    input_values: tuple[str, ...]
    output_values: tuple[str, ...]
    flow_identity: str
    resolved_arguments: dict[str, object]
    resolution: str
    limitations: tuple[str, ...]
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


class _Analyzer:
    def __init__(self, snapshot: ArtifactReadSnapshot, script: ShellScript) -> None:
        self.snapshot = snapshot
        self.script = script
        self.operations: list[_OperationDraft] = []
        self.edges: list[_EdgeDraft] = []
        self.unresolved = set(script.unresolved_constructs)
        self.limitations = set(script.limitations)
        self.ordinal = 0
        self.module_scope = "<module>"
        self.commands_by_scope: dict[str, list[ShellCommand]] = {self.module_scope: []}
        for command in script.commands:
            self.commands_by_scope.setdefault(command.scope, []).append(command)
        self.duplicate_functions = {
            name for name in script.functions if script.functions.count(name) > 1
        }
        self.reachable_scopes = self._reachable_scopes()

    def _reachable_scopes(self) -> set[str]:
        reachable = {self.module_scope}
        changed = True
        while changed:
            changed = False
            for scope in tuple(reachable):
                for command in self.commands_by_scope.get(scope, ()):
                    name = _basename(command.command)
                    if command.condition_state == "unreachable" or name not in self.commands_by_scope:
                        continue
                    if name in self.duplicate_functions:
                        self._remember_unresolved("duplicate_function:" + name)
                        continue
                    if name not in reachable:
                        reachable.add(name)
                        changed = True
        return reachable

    def analyze(self) -> StaticProgramAnalysis:
        scopes = sorted(self.commands_by_scope, key=lambda item: (item != self.module_scope, item))
        for scope in scopes:
            self._analyze_scope(scope, self.commands_by_scope[scope])
        return self._finalize()

    def _analyze_scope(self, scope: str, commands: list[ShellCommand]) -> None:
        variables: dict[str, _ValueState] = {}
        pipeline_state: _ValueState | None = None
        base = "entrypoint_reachable" if scope in self.reachable_scopes else "locally_reachable"
        for command in commands:
            reachability = self._reachability(base, command)
            if command.separator != "|":
                pipeline_state = None
            assignment = _ASSIGNMENT.match(command.words[0]) if command.words else None
            if assignment is not None and len(command.words) == 1:
                self._handle_assignment(command, scope, reachability, variables, assignment)
                continue
            name = _basename(command.command)
            if name in self.commands_by_scope:
                continue
            pipeline_state = self._handle_command(
                command, scope, reachability, variables, pipeline_state,
            )

    @staticmethod
    def _reachability(base: str, command: ShellCommand) -> str:
        if command.condition_state == "unreachable":
            return "unreachable"
        if command.condition_state == "conditional" or command.separator in {"&&", "||"}:
            return "conditionally_reachable"
        return base

    def _variable_states(self, text: str, variables: dict[str, _ValueState]) -> tuple[list[_ValueState], bool]:
        states: list[_ValueState] = []
        unresolved = False
        seen: set[str] = set()
        for match in _VARIABLE.finditer(text):
            name = (match.group("braced") or match.group("plain") or "").casefold()
            if name in seen:
                continue
            seen.add(name)
            state = variables.get(name)
            if state is None:
                unresolved = True
                self._remember_unresolved("unresolved_variable:" + name[:128])
            else:
                states.append(state)
        return states, unresolved

    def _resolve_text(self, text: str, variables: dict[str, _ValueState]) -> tuple[str, list[_ValueState], bool]:
        states, unresolved = self._variable_states(text, variables)
        resolved = text
        for name, state in variables.items():
            if not state.resolved:
                continue
            resolved = re.sub(r"\$\{" + re.escape(name) + r"\}", state.resolved, resolved, flags=re.IGNORECASE)
            resolved = re.sub(r"\$" + re.escape(name) + r"\b", state.resolved, resolved, flags=re.IGNORECASE)
        if "$" in resolved and not states:
            unresolved = True
        return _bounded_text(resolved.strip("'\"")), states, unresolved

    @staticmethod
    def _common_flow(states: list[_ValueState]) -> tuple[str, bool, int | None, str]:
        flowed = [state for state in states if state.flow_identity]
        flows = {state.flow_identity for state in flowed}
        if len(flows) != 1:
            return "", len(flows) > 1, None, ""
        flow = next(iter(flows))
        drafts = {state.source_draft for state in flowed if state.flow_identity == flow}
        values = {state.value_id for state in flowed if state.flow_identity == flow}
        return (
            flow,
            False,
            next(iter(drafts)) if len(drafts) == 1 else None,
            next(iter(values)) if len(values) == 1 else "",
        )

    def _handle_assignment(
        self,
        command: ShellCommand,
        scope: str,
        reachability: str,
        variables: dict[str, _ValueState],
        assignment: re.Match[str],
    ) -> None:
        name = assignment.group("name").casefold()
        value = assignment.group("value")
        value_id = _identity("val_", self.snapshot.content_sha256, scope, name, command.line)
        substitution = _COMMAND_SUBSTITUTION.match(value)
        if substitution is not None:
            target, _states, unresolved = self._resolve_text(substitution.group("path"), variables)
            state = self._source_operation(
                "file_read", command, scope, reachability, target,
                substitution.group("command").casefold(), unresolved,
            )
            variables[name] = _ValueState(value_id, "", state.flow_identity, state.source_draft)
            self._append_edge(_EdgeDraft(
                "assignment", state.flow_identity, state.value_id, value_id,
                state.source_draft, None,
            ))
            return
        resolved, states, unresolved = self._resolve_text(value, variables)
        flow, ambiguous, source_draft, source_value = self._common_flow(states)
        if ambiguous:
            unresolved = True
            flow = ""
            source_draft = None
            source_value = ""
            self._remember_unresolved("ambiguous_variable_flow")
        variables[name] = _ValueState(
            value_id,
            resolved if not unresolved and not states and "$" not in value else "",
            flow,
            source_draft,
        )
        if flow and source_value:
            self._append_edge(_EdgeDraft("assignment", flow, source_value, value_id, source_draft, None))

    def _handle_command(
        self,
        command: ShellCommand,
        scope: str,
        reachability: str,
        variables: dict[str, _ValueState],
        pipeline_state: _ValueState | None,
    ) -> _ValueState | None:
        name = _basename(command.command)
        if not name or "$" in command.command or "`" in command.command:
            self._remember_unresolved("dynamic_command_name")
            return None
        if name in {"eval", "source", "."}:
            self._remember_unresolved("dynamic_shell_evaluation:" + name)
            return None
        raw_states, raw_unresolved = self._variable_states(command.raw, variables)
        raw_flow, ambiguous, source_draft, source_value = self._common_flow(raw_states)
        if ambiguous:
            raw_unresolved = True
            raw_flow = ""
            source_draft = None
            source_value = ""
            self._remember_unresolved("ambiguous_command_flow")
        if pipeline_state is not None:
            if raw_flow and raw_flow != pipeline_state.flow_identity:
                raw_unresolved = True
                raw_flow = ""
                source_draft = None
                source_value = ""
                self._remember_unresolved("ambiguous_pipeline_flow")
            elif not raw_flow:
                raw_flow = pipeline_state.flow_identity
                source_draft = pipeline_state.source_draft
                source_value = pipeline_state.value_id
        input_redirect = next((item for item in command.redirections if item.operator.startswith("<")), None)
        output_redirects = tuple(item for item in command.redirections if item.operator.startswith(">"))
        if input_redirect is not None:
            target, _states, unresolved = self._resolve_text(input_redirect.target, variables)
            state = self._source_operation("file_read", command, scope, reachability, target, "input_redirection", unresolved)
            if raw_flow and raw_flow != state.flow_identity:
                raw_unresolved = True
                raw_flow = ""
                source_draft = None
                source_value = ""
                self._remember_unresolved("ambiguous_redirect_flow")
            elif not raw_flow:
                raw_flow, source_draft, source_value = state.flow_identity, state.source_draft, state.value_id

        output_state: _ValueState | None = None
        if name in {"cat", "head", "tail"} and len(command.words) > 1:
            target, _states, unresolved = self._resolve_text(command.words[-1], variables)
            output_state = self._source_operation("file_read", command, scope, reachability, target, name, unresolved)
        elif name in {"cp", "mv"} and len(command.words) > 2:
            source, _s, source_unresolved = self._resolve_text(command.words[-2], variables)
            target, _t, target_unresolved = self._resolve_text(command.words[-1], variables)
            state = self._source_operation("file_read", command, scope, reachability, source, name, source_unresolved)
            output_state = self._sink_operation(
                "file_write", command, scope, reachability, target, [state],
                {"action": name, "source": source, "target": target}, target_unresolved,
            )
        elif name == "dd":
            source = next((word[3:] for word in command.words[1:] if word.startswith("if=")), "")
            target = next((word[3:] for word in command.words[1:] if word.startswith("of=")), "")
            states: list[_ValueState] = []
            if source:
                source, _s, unresolved = self._resolve_text(source, variables)
                states.append(self._source_operation("file_read", command, scope, reachability, source, "dd", unresolved))
            if target:
                target, _t, unresolved = self._resolve_text(target, variables)
                output_state = self._sink_operation(
                    "file_write", command, scope, reachability, target, states,
                    {"action": "dd", "target": target}, unresolved,
                )
        elif name in {"curl", "wget"}:
            output_state = self._handle_network(command, scope, reachability, variables, raw_flow, source_draft, source_value, raw_unresolved)
        elif name in {"base64", "openssl"}:
            output_state = self._handle_transform(command, scope, reachability, variables, raw_flow, source_draft, source_value, raw_unresolved)
        elif name in {"tar", "zip", "unzip", "gzip", "gunzip"}:
            output_state = self._handle_archive(command, scope, reachability, variables)
        elif name in {"rm", "touch", "mkdir", "chmod", "chown"} and len(command.words) > 1:
            target, _states, unresolved = self._resolve_text(command.words[-1], variables)
            kind = "security_configuration_modify" if name in {"chmod", "chown"} else "file_write"
            output_state = self._sink_operation(kind, command, scope, reachability, target, [], {"action": name, "target": target}, unresolved)
        elif name in {"kill", "killall", "pkill"}:
            target = _basename(command.words[-1]) if len(command.words) > 1 else ""
            self._process_launch(command, scope, reachability, name)
            if target in _SECURITY_PROCESSES:
                self._append_operation(
                    "security_process_terminate", command, scope, reachability, target,
                    (), (), "", {"action": name, "target": target}, "resolved", (),
                )
        elif name in {"systemctl", "service"}:
            self._process_launch(command, scope, reachability, name)
            words = [word.casefold() for word in command.words[1:]]
            target = words[0] if name == "service" and words else (words[-1] if words else "")
            if "stop" in words and target in _SECURITY_SERVICES:
                self._append_operation(
                    "security_service_stop", command, scope, reachability, target,
                    (), (), "", {"action": "stop", "command": name, "target": target}, "resolved", (),
                )
        elif name in _KNOWN_PROCESS_COMMANDS:
            output_state = self._process_launch(command, scope, reachability, name)
        elif name not in _SHELL_BUILTINS:
            self._remember_unresolved("unclassified_command:" + name[:128])

        if output_redirects:
            sources = [output_state] if output_state is not None else []
            if not sources and raw_flow:
                sources = [_ValueState(source_value, "", raw_flow, source_draft)]
            for redirect in output_redirects:
                target, _states, unresolved = self._resolve_text(redirect.target, variables)
                output_state = self._sink_operation(
                    "file_write", command, scope, reachability, target, sources,
                    {"action": "output_redirection", "path": target}, unresolved,
                )
        return output_state

    def _handle_network(
        self,
        command: ShellCommand,
        scope: str,
        reachability: str,
        variables: dict[str, _ValueState],
        raw_flow: str,
        source_draft: int | None,
        source_value: str,
        raw_unresolved: bool,
    ) -> _ValueState | None:
        name = _basename(command.command)
        words = command.words[1:]
        url = next((word for word in reversed(words) if _URL.match(word)), "")
        output = self._option_value(words, ("-o", "--output", "-O"))
        upload = self._option_value(words, ("-T", "--upload-file"))
        data = self._option_value(words, ("-d", "--data", "--data-binary", "--data-raw"))
        if upload:
            target, _states, unresolved = self._resolve_text(upload, variables)
            state = self._source_operation("file_read", command, scope, reachability, target, name, unresolved)
            return self._sink_operation(
                "network_upload", command, scope, reachability, url, [state],
                {"command": name, "source": target, "url": url}, not bool(url),
            )
        if data or raw_flow:
            states, unresolved = self._variable_states(data or command.raw, variables)
            flow, ambiguous, source_draft2, source_value2 = self._common_flow(states)
            if not flow:
                flow, source_draft2, source_value2 = raw_flow, source_draft, source_value
            limitations: tuple[str, ...] = ()
            if ambiguous:
                flow = ""
                source_draft2 = None
                source_value2 = ""
                limitations = ("ambiguous_source_flow",)
            resolution = "partial" if unresolved or raw_unresolved or ambiguous or not url else "resolved"
            operation_limitations = limitations + (("unresolved_network_target",) if not url else ())
            for kind in ("network_send", "network_upload"):
                index = self._append_operation(
                    kind, command, scope, reachability, url,
                    (source_value2,) if source_value2 else (), (), flow,
                    {"command": name, "url": url},
                    resolution,
                    operation_limitations,
                )
                if flow and source_value2 and index is not None:
                    self._append_edge(_EdgeDraft("source_to_sink", flow, source_value2, _identity("val_", self.snapshot.content_sha256, kind + "_sink", index), source_draft2, index))
            return None
        if output or name == "wget":
            flow = _identity("flow_", self.snapshot.content_sha256, scope, "download", command.line, command.column)
            value = _identity("val_", self.snapshot.content_sha256, scope, "download", command.line, command.column)
            index = self._append_operation(
                "network_download", command, scope, reachability, url, (), (value,), flow,
                {"command": name, "url": url}, "partial" if not url else "resolved",
                (("unresolved_network_target",) if not url else ()),
            )
            state = _ValueState(value, "", flow, index)
            if output:
                target, _states, unresolved = self._resolve_text(output, variables)
                return self._sink_operation("file_write", command, scope, reachability, target, [state], {"action": "download_output", "target": target}, unresolved)
            return state
        self._append_operation(
            "network_connect", command, scope, reachability, url, (), (), "",
            {"command": name, "url": url}, "partial" if not url else "resolved",
            (("unresolved_network_target",) if not url else ()),
        )
        return None

    def _handle_transform(
        self,
        command: ShellCommand,
        scope: str,
        reachability: str,
        variables: dict[str, _ValueState],
        raw_flow: str,
        source_draft: int | None,
        source_value: str,
        raw_unresolved: bool,
    ) -> _ValueState | None:
        name = _basename(command.command)
        decode = any(word.casefold() in {"-d", "--decode", "-decode", "-decrypt"} for word in command.words[1:])
        if not decode:
            return None
        source = next((word for word in command.words[1:] if not word.startswith("-") and not _URL.match(word)), "")
        state: _ValueState | None = None
        if source:
            source, _states, unresolved = self._resolve_text(source, variables)
            state = self._source_operation("file_read", command, scope, reachability, source, name, unresolved)
        elif raw_flow:
            state = _ValueState(source_value, "", raw_flow, source_draft)
        input_values = (state.value_id,) if state and state.value_id else ()
        flow = state.flow_identity if state else ""
        value = _identity("val_", self.snapshot.content_sha256, scope, "decode", command.line, command.column)
        index = self._append_operation(
            "decode", command, scope, reachability, "", input_values, (value,), flow,
            {"command": name}, "partial" if raw_unresolved or state is None else "resolved",
            (("unresolved_transform_input",) if state is None else ()),
        )
        if state and flow:
            self._append_edge(_EdgeDraft("source_to_sink", flow, state.value_id, value, state.source_draft, index))
        return _ValueState(value, "", flow, index)

    def _handle_archive(self, command: ShellCommand, scope: str, reachability: str, variables: dict[str, _ValueState]) -> _ValueState | None:
        name = _basename(command.command)
        words = command.words[1:]
        extracting = name in {"unzip", "gunzip"} or any("x" in word.lstrip("-") for word in words[:2])
        kind = "decompress" if extracting else "archive"
        source = next((word for word in reversed(words) if not word.startswith("-")), "")
        state: _ValueState | None = None
        if source:
            source, _states, unresolved = self._resolve_text(source, variables)
            state = self._source_operation("file_read", command, scope, reachability, source, name, unresolved)
        value = _identity("val_", self.snapshot.content_sha256, scope, kind, command.line, command.column)
        flow = state.flow_identity if state else ""
        index = self._append_operation(
            kind, command, scope, reachability, source,
            (state.value_id,) if state else (), (value,), flow,
            {"command": name, "source": source}, "partial" if not source else "resolved",
            (("unresolved_archive_source",) if not source else ()),
        )
        if state and flow:
            self._append_edge(_EdgeDraft("source_to_sink", flow, state.value_id, value, state.source_draft, index))
        return _ValueState(value, "", flow, index)

    @staticmethod
    def _option_value(words: tuple[str, ...], options: tuple[str, ...]) -> str:
        for index, word in enumerate(words):
            lowered = word.casefold()
            if lowered in options and index + 1 < len(words):
                return words[index + 1]
            for option in options:
                if lowered.startswith(option + "="):
                    return word[len(option) + 1:]
        return ""

    def _process_launch(self, command: ShellCommand, scope: str, reachability: str, name: str) -> _ValueState | None:
        index = self._append_operation(
            "process_launch", command, scope, reachability, name, (), (), "",
            {"arguments": list(command.words[1:]), "command": name}, "resolved", (),
        )
        return None if index is None else _ValueState("", "", "", index)

    def _source_operation(
        self,
        kind: str,
        command: ShellCommand,
        scope: str,
        reachability: str,
        target: str,
        action: str,
        unresolved: bool,
    ) -> _ValueState:
        flow = _identity("flow_", self.snapshot.content_sha256, scope, kind, command.line, command.column, target)
        value = _identity("val_", self.snapshot.content_sha256, scope, kind, command.line, command.column, target)
        index = self._append_operation(
            kind, command, scope, reachability, target, (), (value,), flow,
            {"action": action, "path": target}, "partial" if unresolved else "resolved",
            (("unresolved_path",) if unresolved else ()),
        )
        return _ValueState(value, "", flow, index)

    def _sink_operation(
        self,
        kind: str,
        command: ShellCommand,
        scope: str,
        reachability: str,
        target: str,
        states: list[_ValueState],
        arguments: dict[str, object],
        unresolved: bool,
    ) -> _ValueState:
        flow, ambiguous, source_draft, source_value = self._common_flow(states)
        limitations: list[str] = []
        if ambiguous:
            flow = ""
            source_draft = None
            source_value = ""
            unresolved = True
            limitations.append("ambiguous_source_flow")
        output_value = _identity("val_", self.snapshot.content_sha256, scope, kind, command.line, command.column, target)
        index = self._append_operation(
            kind, command, scope, reachability, target,
            (source_value,) if source_value else (), (output_value,), flow,
            arguments, "partial" if unresolved else "resolved", tuple(limitations),
        )
        if flow and source_value:
            self._append_edge(_EdgeDraft("source_to_sink", flow, source_value, output_value, source_draft, index))
        return _ValueState(output_value, "", flow, index)

    def _append_operation(
        self,
        kind: str,
        command: ShellCommand,
        scope: str,
        reachability: str,
        target: str,
        input_values: tuple[str, ...],
        output_values: tuple[str, ...],
        flow_identity: str,
        resolved_arguments: dict[str, object],
        resolution: str,
        limitations: tuple[str, ...],
    ) -> int | None:
        if len(self.operations) >= SHELL_MAX_OPERATIONS:
            self.limitations.add("operation_limit_exceeded")
            return None
        self.operations.append(_OperationDraft(
            kind=kind,
            command=command,
            scope=scope,
            ordinal=self.ordinal,
            reachability=reachability,
            target=_bounded_text(target),
            input_values=input_values,
            output_values=output_values,
            flow_identity=flow_identity,
            resolved_arguments=dict(resolved_arguments),
            resolution=resolution,
            limitations=tuple(item for item in limitations if item),
        ))
        self.ordinal += 1
        return len(self.operations) - 1

    def _append_edge(self, edge: _EdgeDraft) -> None:
        if len(self.edges) >= SHELL_MAX_FLOW_EDGES:
            self.limitations.add("flow_edge_limit_exceeded")
            return
        self.edges.append(edge)

    def _remember_unresolved(self, value: str) -> None:
        if len(self.unresolved) >= SHELL_MAX_UNRESOLVED:
            self.limitations.add("unresolved_construct_limit_exceeded")
            return
        self.unresolved.add(value[:512])

    def _finalize(self) -> StaticProgramAnalysis:
        scopes = tuple(sorted(self.commands_by_scope, key=lambda item: (item != self.module_scope, item)))
        function_ids = {scope: _identity("fn_", self.snapshot.content_sha256, "shell_scope", scope) for scope in scopes}
        actor_ids = {scope: _identity("spe_", self.snapshot.content_sha256, "shell_scope", scope) for scope in scopes}
        for draft in self.operations:
            draft.operation = StaticOperation.create(
                language="shell",
                operation_kind=draft.kind,
                source_location=StaticSourceLocation(
                    locator=static_artifact_identity(self.snapshot.content_sha256),
                    line=draft.command.line,
                    column=draft.command.column,
                    end_line=draft.command.end_line,
                    end_column=draft.command.end_column,
                ),
                enclosing_function_id=function_ids[draft.scope],
                basic_block_id=_identity("bb_", self.snapshot.content_sha256, draft.scope, draft.command.line),
                control_flow_ordinal=draft.ordinal,
                control_flow_provenance="static_control_flow",
                reachability_state=draft.reachability,
                platform="linux",
                actor_program_entity=actor_ids[draft.scope],
                target_resource_identity=(
                    _identity("res_", self.snapshot.content_sha256, draft.kind, draft.target)
                    if draft.target else ""
                ),
                input_value_ids=draft.input_values,
                output_value_ids=draft.output_values,
                flow_identity=draft.flow_identity,
                resolved_arguments=draft.resolved_arguments,
                resolution_state=draft.resolution,
                limitations=draft.limitations,
                integrity_status="verified" if draft.resolution == "resolved" else "partial",
            )
        finalized_edges: list[StaticFlowEdge] = []
        for edge in self.edges:
            source = self.operations[edge.source_draft].operation if edge.source_draft is not None else None
            target = self.operations[edge.target_draft].operation if edge.target_draft is not None else None
            finalized_edges.append(StaticFlowEdge.create(
                flow_identity=edge.flow_identity,
                edge_kind=edge.kind,
                source_value_id=edge.source_value_id,
                target_value_id=edge.target_value_id,
                source_operation_id="" if source is None else source.operation_id,
                target_operation_id="" if target is None else target.operation_id,
                resolution_state=edge.resolution,
                limitations=edge.limitations,
                integrity_status="verified" if edge.resolution == "resolved" else "partial",
            ))
        limited = bool(self.limitations & {
            "command_limit_exceeded", "flow_edge_limit_exceeded", "function_limit_exceeded",
            "operation_limit_exceeded", "unresolved_construct_limit_exceeded",
        })
        return StaticProgramAnalysis(
            content_sha256=self.snapshot.content_sha256,
            content_size=self.snapshot.size,
            artifact_identity=static_artifact_identity(self.snapshot.content_sha256),
            language="shell",
            language_version="posix_shell_structure_v1",
            parser_status="truncated" if limited else "complete",
            parser_schema_version=SHELL_FRONTEND_SCHEMA_VERSION,
            parser_digest=SHELL_FRONTEND_DIGEST,
            operations=tuple(draft.operation for draft in self.operations if draft.operation is not None),
            flow_edges=tuple(finalized_edges),
            entrypoint_function_ids=(function_ids[self.module_scope],),
            unresolved_constructs=tuple(sorted(self.unresolved)),
            limitations=tuple(sorted(self.limitations)),
            integrity_status="partial" if limited else "verified",
        )


def _unavailable(snapshot: ArtifactReadSnapshot, reason: str, *, status: str = "unavailable") -> StaticProgramAnalysis:
    return StaticProgramAnalysis(
        content_sha256=snapshot.content_sha256,
        content_size=snapshot.size,
        artifact_identity=static_artifact_identity(snapshot.content_sha256),
        language="shell",
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
        unavailable_reason=reason[:512],
    )


def _truncated(snapshot: ArtifactReadSnapshot, limitation: str) -> StaticProgramAnalysis:
    return StaticProgramAnalysis(
        content_sha256=snapshot.content_sha256,
        content_size=snapshot.size,
        artifact_identity=static_artifact_identity(snapshot.content_sha256),
        language="shell",
        language_version="posix_shell_structure_v1",
        parser_status="truncated",
        parser_schema_version=SHELL_FRONTEND_SCHEMA_VERSION,
        parser_digest=SHELL_FRONTEND_DIGEST,
        operations=(),
        flow_edges=(),
        entrypoint_function_ids=(),
        unresolved_constructs=(),
        limitations=(limitation,),
        integrity_status="partial",
    )


def _decode_shell_source(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", "strict")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", "strict")
    if b"\x00" in raw:
        raise UnicodeDecodeError("utf-8", raw, 0, min(1, len(raw)), "shell_encoding_bom_required")
    return raw.decode("utf-8", "strict")


def analyze_shell_snapshot(snapshot: object) -> ShellAnalysisResult:
    """Analyze one exact .sh artifact through the canonical SQLite cache."""
    owned = require_artifact_read_snapshot(snapshot)
    if owned.extension.lower() != ".sh":
        raise ValueError("shell_extension_not_applicable")
    if not owned.complete:
        return ShellAnalysisResult(_unavailable(owned, owned.unavailable_reason or "artifact_read_unavailable"), "computed")
    dependency = shell_analysis_dependency_digest()
    hit = scan_cache_repository().get_static_analysis(
        content_sha256=owned.content_sha256,
        analysis_dependency_digest=dependency,
    )
    if hit is not None:
        return ShellAnalysisResult(hit.analysis, "sqlite_cache")
    if owned.size > SHELL_MAX_SOURCE_BYTES or owned.prefix_truncated:
        analysis = _truncated(owned, "source_size_limit_exceeded")
    else:
        raw = owned.read_prefix(owned.size)
        try:
            analysis = _Analyzer(owned, parse_shell(_decode_shell_source(raw))).analyze()
        except UnicodeDecodeError as exc:
            analysis = _unavailable(owned, "parser_failed:" + type(exc).__name__, status="failed")
        except (ShellSyntaxError, TypeError, ValueError) as exc:
            analysis = _unavailable(
                owned,
                "parser_failed:" + type(exc).__name__ + ":" + str(exc)[:320],
                status="failed",
            )
    scan_cache_repository().put_static_analysis(
        content_sha256=owned.content_sha256,
        content_size=owned.size,
        analysis_dependency_digest=dependency,
        analysis=analysis,
    )
    return ShellAnalysisResult(analysis, "computed")


__all__ = (
    "SHELL_FRONTEND_DIGEST",
    "SHELL_FRONTEND_SCHEMA_VERSION",
    "SHELL_MAX_SOURCE_BYTES",
    "ShellAnalysisResult",
    "analyze_shell_snapshot",
    "shell_analysis_dependency_digest",
)
