"""Bounded canonical Windows Batch/CMD static-program-analysis frontend.

The frontend parses command-script structure without invoking ``cmd.exe`` or
expanding the host environment.  It emits only language-neutral physical
operations, reachability, and reproducible local value-flow relations.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import PureWindowsPath
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
from Virus_Scan.scanners.static_program_analysis.batch_cmd_syntax import (
    BATCH_CMD_MAX_COMMANDS,
    BATCH_CMD_MAX_CONTINUATIONS,
    BATCH_CMD_MAX_LABELS,
    BATCH_CMD_MAX_LINE_LENGTH,
    BATCH_CMD_MAX_LOGICAL_LINES,
    BATCH_CMD_MAX_PHYSICAL_LINES,
    BATCH_CMD_MAX_WORDS,
    BatchCmdCommand,
    BatchCmdScript,
    BatchCmdSyntaxError,
    parse_batch_cmd,
)
from Virus_Scan.storage import scan_cache_repository

BATCH_CMD_FRONTEND_SCHEMA_VERSION = "batch_cmd_static_frontend_v3"
BATCH_CMD_MAX_SOURCE_BYTES = 1_500_000
BATCH_CMD_MAX_OPERATIONS = 4_096
BATCH_CMD_MAX_FLOW_EDGES = 4_096
BATCH_CMD_MAX_UNRESOLVED = 256
BATCH_CMD_MAX_CONSTANT_TEXT = 4_096

_PERCENT_VARIABLE = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")
_DELAYED_VARIABLE = re.compile(r"!([A-Za-z_][A-Za-z0-9_]*)!")
_SET_ASSIGNMENT = re.compile(r"^(?:/a\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$", re.IGNORECASE)
_URL = re.compile(r"^https?://", re.IGNORECASE)
_SECURITY_PROCESS_TARGETS = frozenset({
    "csfalconservice.exe", "msmpeng.exe", "securityhealthservice.exe",
    "senseir.exe", "sysmon.exe", "sysmon64.exe",
})
_SECURITY_SERVICE_TARGETS = frozenset({
    "csagent", "sense", "securityhealthservice", "sysmon", "windefend",
})
_PROCESS_COMMANDS = frozenset({
    "bitsadmin", "bitsadmin.exe", "certutil", "certutil.exe", "cmd", "cmd.exe",
    "cscript", "cscript.exe", "mshta", "mshta.exe", "powershell", "powershell.exe",
    "pwsh", "pwsh.exe", "reg", "reg.exe", "regsvr32", "regsvr32.exe",
    "rundll32", "rundll32.exe", "schtasks", "schtasks.exe", "start",
    "taskkill", "taskkill.exe", "wmic", "wmic.exe", "wscript", "wscript.exe",
})
_NON_PROCESS_BUILTINS = frozenset({
    "break", "cd", "chcp", "chdir", "cls", "color", "date", "echo", "else",
    "endlocal", "exit", "for", "goto", "if", "md", "mkdir", "path", "pause",
    "popd", "prompt", "pushd", "rd", "rem", "ren", "rename", "rmdir", "set",
    "setlocal", "shift", "time", "title", "type", "ver", "verify", "vol",
})
_SOURCE_KINDS = frozenset({"file_read", "network_download"})


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    return hashlib.sha256(encoded).hexdigest()


BATCH_CMD_FRONTEND_DIGEST = _canonical_digest({
    "frontend_schema": BATCH_CMD_FRONTEND_SCHEMA_VERSION,
    "ir_schema": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    "ir_schema_digest": STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    "limits": {
        "commands": BATCH_CMD_MAX_COMMANDS,
        "continuations": BATCH_CMD_MAX_CONTINUATIONS,
        "flow_edges": BATCH_CMD_MAX_FLOW_EDGES,
        "labels": BATCH_CMD_MAX_LABELS,
        "line_length": BATCH_CMD_MAX_LINE_LENGTH,
        "logical_lines": BATCH_CMD_MAX_LOGICAL_LINES,
        "operations": BATCH_CMD_MAX_OPERATIONS,
        "physical_lines": BATCH_CMD_MAX_PHYSICAL_LINES,
        "source_bytes": BATCH_CMD_MAX_SOURCE_BYTES,
        "words": BATCH_CMD_MAX_WORDS,
    },
    "syntax_owner": "bounded_batch_cmd_structure_v1",
})


def batch_cmd_analysis_dependency_digest() -> str:
    return BATCH_CMD_FRONTEND_DIGEST


def _identity(prefix: str, *parts: object) -> str:
    return prefix + _canonical_digest([str(part) for part in parts])[:40]


def _bounded_text(value: object) -> str:
    return str(value)[:BATCH_CMD_MAX_CONSTANT_TEXT]


def _command_basename(value: str) -> str:
    text = value.strip().strip('"').replace("/", "\\")
    return PureWindowsPath(text).name.casefold() if text else ""


def _label_target(value: str) -> str:
    text = value.strip().casefold()
    if text.startswith(":"):
        text = text[1:]
    return text


@dataclass(frozen=True, slots=True)
class BatchCmdAnalysisResult:
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
    command: BatchCmdCommand
    scope: str
    block: str
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
    def __init__(self, snapshot: ArtifactReadSnapshot, script: BatchCmdScript) -> None:
        self.snapshot = snapshot
        self.script = script
        self.operations: list[_OperationDraft] = []
        self.edges: list[_EdgeDraft] = []
        self.unresolved = set(script.unresolved_constructs)
        self.limitations = set(script.limitations)
        self.ordinal = 0
        self.module_scope = "<module>"
        self.label_lines: list[tuple[int, str]] = []
        self.duplicate_labels: set[str] = set()
        seen: set[str] = set()
        for label in script.labels:
            if label.name in seen:
                self.duplicate_labels.add(label.name)
            seen.add(label.name)
            self.label_lines.append((label.line, label.name))
        self.label_lines.sort()
        self.commands_by_scope: dict[str, list[BatchCmdCommand]] = {self.module_scope: []}
        for command in script.commands:
            scope = self.module_scope
            for line, label in self.label_lines:
                if line >= command.line:
                    break
                scope = label
            self.commands_by_scope.setdefault(scope, []).append(command)
        self.reachable_scopes = self._reachable_scopes()

    def _reachable_scopes(self) -> set[str]:
        reachable = {self.module_scope}
        changed = True
        while changed:
            changed = False
            for scope in tuple(reachable):
                for command in self.commands_by_scope.get(scope, ()):
                    if command.condition_state == "unreachable" or len(command.words) < 2:
                        continue
                    if command.command not in {"call", "goto"}:
                        continue
                    target = _label_target(command.words[1])
                    if (
                        not command.words[1].startswith(":") and command.command == "call"
                    ):
                        continue
                    if "%" in target or "!" in target:
                        self._remember_unresolved("dynamic_label_target")
                        continue
                    if target in self.duplicate_labels:
                        self._remember_unresolved("duplicate_label:" + target)
                        continue
                    if target in self.commands_by_scope and target not in reachable:
                        reachable.add(target)
                        changed = True
        return reachable

    def analyze(self) -> StaticProgramAnalysis:
        for scope in sorted(self.commands_by_scope, key=lambda item: (item != self.module_scope, item)):
            self._analyze_scope(scope, self.commands_by_scope[scope])
        return self._finalize()

    def _analyze_scope(self, scope: str, commands: list[BatchCmdCommand]) -> None:
        variables: dict[str, _ValueState] = {}
        delayed = False
        base_reachability = "entrypoint_reachable" if scope in self.reachable_scopes else "locally_reachable"
        for command in commands:
            reachability = self._reachability(base_reachability, command)
            if command.command == "setlocal":
                delayed = any("enabledelayedexpansion" in word.casefold() for word in command.words[1:])
                continue
            if command.command == "endlocal":
                delayed = False
                variables.clear()
                continue
            if command.command == "set":
                self._handle_set(command, scope, reachability, variables, delayed)
                continue
            if command.command in {"goto", "exit"}:
                if len(command.words) > 1 and any(marker in command.words[1] for marker in ("%", "!")):
                    self._remember_unresolved("dynamic_control_flow_target")
                continue
            if command.command == "call" and len(command.words) > 1 and command.words[1].startswith(":"):
                continue
            self._handle_command(command, scope, reachability, variables, delayed)

    @staticmethod
    def _reachability(base: str, command: BatchCmdCommand) -> str:
        if command.condition_state == "unreachable":
            return "unreachable"
        if command.condition_state == "conditional" or command.separator in {"&&", "||"}:
            return "conditionally_reachable"
        return base

    def _variable_states(
        self,
        text: str,
        variables: dict[str, _ValueState],
        delayed: bool,
    ) -> tuple[list[_ValueState], bool]:
        names = [match.group(1).casefold() for match in _PERCENT_VARIABLE.finditer(text)]
        delayed_names = [match.group(1).casefold() for match in _DELAYED_VARIABLE.finditer(text)]
        unresolved = False
        if delayed_names and not delayed:
            self._remember_unresolved("delayed_expansion_without_setlocal")
            unresolved = True
        elif delayed:
            names.extend(delayed_names)
        states: list[_ValueState] = []
        seen: set[str] = set()
        for name in names:
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

    def _resolve_text(
        self,
        text: str,
        variables: dict[str, _ValueState],
        delayed: bool,
    ) -> tuple[str, list[_ValueState], bool]:
        states, unresolved = self._variable_states(text, variables, delayed)
        resolved = text
        for name, state in variables.items():
            if state.resolved:
                resolved = re.sub(r"%" + re.escape(name) + r"%", state.resolved, resolved, flags=re.IGNORECASE)
                if delayed:
                    resolved = re.sub(r"!" + re.escape(name) + r"!", state.resolved, resolved, flags=re.IGNORECASE)
        resolved = re.sub(r"%~dp0", lambda _match: "script_directory\\", resolved, flags=re.IGNORECASE)
        return _bounded_text(resolved), states, unresolved

    @staticmethod
    def _common_flow(states: list[_ValueState]) -> tuple[str, bool, int | None, str]:
        flowed = [state for state in states if state.flow_identity]
        flows = {state.flow_identity for state in flowed}
        if len(flows) != 1:
            return "", len(flows) > 1, None, ""
        flow = next(iter(flows))
        source_drafts = {state.source_draft for state in flowed if state.flow_identity == flow}
        source_draft = next(iter(source_drafts)) if len(source_drafts) == 1 else None
        source_values = {state.value_id for state in flowed if state.flow_identity == flow}
        source_value = next(iter(source_values)) if len(source_values) == 1 else ""
        return flow, False, source_draft, source_value

    def _handle_set(
        self,
        command: BatchCmdCommand,
        scope: str,
        reachability: str,
        variables: dict[str, _ValueState],
        delayed: bool,
    ) -> None:
        words = list(command.words[1:])
        interactive = bool(words and words[0].casefold() == "/p")
        if interactive:
            words = words[1:]
        assignment_text = " ".join(words).strip().strip('"')
        match = _SET_ASSIGNMENT.match(assignment_text)
        if match is None:
            self._remember_unresolved("dynamic_set_assignment")
            return
        name = match.group("name").casefold()
        value = match.group("value")
        input_redirect = next((item.target for item in command.redirections if item.operator == "<"), "")
        value_id = _identity("val_", self.snapshot.content_sha256, scope, name, command.line)
        if interactive and input_redirect:
            target, _states, unresolved = self._resolve_text(input_redirect, variables, delayed)
            flow = _identity("flow_", self.snapshot.content_sha256, scope, name, command.line)
            index = self._append_operation(
                "file_read", command, scope, reachability, target,
                (), (value_id,), flow,
                {"action": "set_p_input", "command": "set", "path": target},
                "partial" if unresolved else "resolved",
                ("unresolved_path" if unresolved else "",),
            )
            variables[name] = _ValueState(value_id, "", flow, index)
            return
        resolved, states, unresolved = self._resolve_text(value, variables, delayed)
        flow, ambiguous, source_draft, source_value = self._common_flow(states)
        if ambiguous:
            flow = ""
            source_draft = None
            source_value = ""
            unresolved = True
            self._remember_unresolved("ambiguous_variable_flow")
        variables[name] = _ValueState(value_id, resolved if not unresolved and not states else "", flow, source_draft)
        if flow and source_value:
            self._append_edge(_EdgeDraft(
                "assignment", flow, source_value, value_id, source_draft, None,
            ))

    def _handle_command(
        self,
        command: BatchCmdCommand,
        scope: str,
        reachability: str,
        variables: dict[str, _ValueState],
        delayed: bool,
    ) -> None:
        name = _command_basename(command.command)
        raw_states, raw_unresolved = self._variable_states(command.raw, variables, delayed)
        raw_flow, ambiguous, source_draft, source_value = self._common_flow(raw_states)
        if ambiguous:
            raw_flow = ""
            source_draft = None
            source_value = ""
            raw_unresolved = True
            self._remember_unresolved("ambiguous_command_flow")
        input_redirects = [item for item in command.redirections if item.operator == "<"]
        output_redirects = [item for item in command.redirections if item.operator in {">", ">>"}]
        redirected_source: _ValueState | None = None
        if input_redirects:
            target, _states, unresolved = self._resolve_text(input_redirects[0].target, variables, delayed)
            flow = _identity("flow_", self.snapshot.content_sha256, scope, "redir", command.line, command.column)
            value_id = _identity("val_", self.snapshot.content_sha256, scope, "redir", command.line, command.column)
            index = self._append_operation(
                "file_read", command, scope, reachability, target, (), (value_id,), flow,
                {"action": "input_redirection", "path": target},
                "partial" if unresolved else "resolved",
                ("unresolved_path" if unresolved else "",),
            )
            redirected_source = _ValueState(value_id, "", flow, index)
            if not raw_flow:
                raw_flow, source_draft, source_value = flow, index, value_id
        handled = False
        if name == "type" and len(command.words) > 1:
            target, _states, unresolved = self._resolve_text(command.words[1], variables, delayed)
            self._source_operation("file_read", command, scope, reachability, target, "type", unresolved)
            handled = True
        elif name in {"copy", "xcopy", "robocopy", "move"} and len(command.words) > 2:
            source, _source_states, source_unresolved = self._resolve_text(command.words[-2], variables, delayed)
            target, _target_states, target_unresolved = self._resolve_text(command.words[-1], variables, delayed)
            source_state = self._source_operation("file_read", command, scope, reachability, source, name, source_unresolved)
            self._sink_operation(
                "file_write", command, scope, reachability, target, [source_state],
                {"action": name, "source": source, "target": target},
                target_unresolved,
            )
            handled = True
        elif name in {"certutil", "certutil.exe"}:
            handled = self._handle_certutil(command, scope, reachability, variables, delayed)
        elif name in {"curl", "curl.exe"}:
            handled = self._handle_curl(command, scope, reachability, variables, delayed)
        elif name in {"bitsadmin", "bitsadmin.exe"}:
            handled = self._handle_bitsadmin(command, scope, reachability, variables, delayed)
        elif name in {"reg", "reg.exe"} and len(command.words) > 2:
            action = command.words[1].casefold()
            target, states, unresolved = self._resolve_text(command.words[2], variables, delayed)
            self._sink_operation(
                "registry_access", command, scope, reachability, target, states,
                {"action": action, "command": name, "target": target}, unresolved,
            )
            handled = True
        elif name in {"taskkill", "taskkill.exe"}:
            handled = True
            target = self._option_value(command.words[1:], "/im")
            self._process_launch(command, scope, reachability, variables, delayed)
            if target and target.casefold() in _SECURITY_PROCESS_TARGETS:
                self._sink_operation(
                    "security_process_terminate", command, scope, reachability, target, [],
                    {"action": "terminate", "process": target}, False,
                )
            elif target:
                self._remember_unresolved("generic_process_terminate:" + target[:128])
        elif name in {"sc", "sc.exe", "net", "net.exe"} and len(command.words) > 2:
            action = command.words[1].casefold()
            target = command.words[2].casefold()
            self._process_launch(command, scope, reachability, variables, delayed)
            if action == "stop" and target in _SECURITY_SERVICE_TARGETS:
                self._sink_operation(
                    "security_service_stop", command, scope, reachability, target, [],
                    {"action": "stop", "service": target}, False,
                )
            elif action == "stop":
                self._remember_unresolved("generic_service_stop:" + target[:128])
            handled = True
        elif self._is_process_command(name, command):
            self._process_launch(command, scope, reachability, variables, delayed)
            handled = True
        elif name in {"del", "erase", "rd", "rmdir", "ren", "rename", "md", "mkdir"} and len(command.words) > 1:
            target, states, unresolved = self._resolve_text(command.words[-1], variables, delayed)
            self._sink_operation(
                "file_write", command, scope, reachability, target, states,
                {"action": name, "path": target}, unresolved,
            )
            handled = True
        if output_redirects:
            for redirect in output_redirects:
                target, states, unresolved = self._resolve_text(redirect.target, variables, delayed)
                combined = list(states)
                if redirected_source is not None:
                    combined.append(redirected_source)
                combined.extend(raw_states)
                self._sink_operation(
                    "file_write", command, scope, reachability, target, combined,
                    {"action": "append" if redirect.operator == ">>" else "overwrite", "path": target},
                    unresolved or raw_unresolved,
                )
            handled = True
        if not handled and name not in _NON_PROCESS_BUILTINS:
            if any(marker in command.command for marker in ("%", "!")):
                self._remember_unresolved("dynamic_command_name")
            elif name:
                self._remember_unresolved("unclassified_command:" + name[:128])

    def _handle_certutil(
        self,
        command: BatchCmdCommand,
        scope: str,
        reachability: str,
        variables: dict[str, _ValueState],
        delayed: bool,
    ) -> bool:
        lowered = [word.casefold() for word in command.words[1:]]
        if "-decode" in lowered and len(command.words) >= 4:
            source, _states, source_unresolved = self._resolve_text(command.words[-2], variables, delayed)
            target, _target_states, target_unresolved = self._resolve_text(command.words[-1], variables, delayed)
            source_state = self._source_operation("file_read", command, scope, reachability, source, "certutil_decode", source_unresolved)
            transformed = self._sink_operation(
                "decode", command, scope, reachability, target, [source_state],
                {"action": "certutil_decode", "source": source, "target": target},
                target_unresolved,
                output=True,
            )
            self._sink_operation(
                "file_write", command, scope, reachability, target, [transformed],
                {"action": "certutil_decode_output", "path": target}, target_unresolved,
            )
            return True
        url = next((word for word in command.words[1:] if _URL.match(word)), "")
        if "-urlcache" in lowered and url:
            target = command.words[-1] if command.words[-1] != url else ""
            source_state = self._source_operation("network_download", command, scope, reachability, url, "certutil_urlcache", False)
            if target:
                resolved, _states, unresolved = self._resolve_text(target, variables, delayed)
                self._sink_operation(
                    "file_write", command, scope, reachability, resolved, [source_state],
                    {"action": "certutil_urlcache_output", "path": resolved}, unresolved,
                )
            return True
        self._process_launch(command, scope, reachability, variables, delayed)
        return True

    def _handle_curl(
        self,
        command: BatchCmdCommand,
        scope: str,
        reachability: str,
        variables: dict[str, _ValueState],
        delayed: bool,
    ) -> bool:
        args = list(command.words[1:])
        url = next((word for word in args if _URL.match(word)), "")
        data_flags = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"}
        upload_flags = {"-t", "--upload-file"}
        data_values: list[str] = []
        upload_values: list[str] = []
        output = ""
        for index, word in enumerate(args):
            lower = word.casefold()
            if lower in data_flags and index + 1 < len(args):
                data_values.append(args[index + 1])
            elif lower in upload_flags and index + 1 < len(args):
                upload_values.append(args[index + 1])
            elif lower in {"-o", "--output"} and index + 1 < len(args):
                output = args[index + 1]
        if upload_values:
            states: list[_ValueState] = []
            unresolved = False
            for value in upload_values:
                path, _vars, path_unresolved = self._resolve_text(value, variables, delayed)
                states.append(self._source_operation("file_read", command, scope, reachability, path, "curl_upload_file", path_unresolved))
                unresolved = unresolved or path_unresolved
            self._sink_operation(
                "network_upload", command, scope, reachability, url, states,
                {"action": "curl_upload", "url": url}, unresolved or not bool(url),
            )
            return True
        if data_values:
            states: list[_ValueState] = []
            unresolved = not bool(url)
            for value in data_values:
                _resolved, value_states, value_unresolved = self._resolve_text(value, variables, delayed)
                states.extend(value_states)
                unresolved = unresolved or value_unresolved
            self._sink_operation(
                "network_send", command, scope, reachability, url, states,
                {"action": "curl_data", "url": url}, unresolved,
            )
            self._sink_operation(
                "network_upload", command, scope, reachability, url, states,
                {"action": "curl_data_upload", "url": url}, unresolved,
            )
            return True
        if url:
            source = self._source_operation("network_download", command, scope, reachability, url, "curl_download", False)
            if output:
                path, _states, unresolved = self._resolve_text(output, variables, delayed)
                self._sink_operation(
                    "file_write", command, scope, reachability, path, [source],
                    {"action": "curl_output", "path": path}, unresolved,
                )
            return True
        self._process_launch(command, scope, reachability, variables, delayed)
        return True

    def _handle_bitsadmin(
        self,
        command: BatchCmdCommand,
        scope: str,
        reachability: str,
        variables: dict[str, _ValueState],
        delayed: bool,
    ) -> bool:
        url_index = next((index for index, word in enumerate(command.words) if _URL.match(word)), -1)
        if url_index >= 0:
            url = command.words[url_index]
            source = self._source_operation("network_download", command, scope, reachability, url, "bitsadmin_transfer", False)
            if url_index + 1 < len(command.words):
                path, _states, unresolved = self._resolve_text(command.words[url_index + 1], variables, delayed)
                self._sink_operation(
                    "file_write", command, scope, reachability, path, [source],
                    {"action": "bitsadmin_output", "path": path}, unresolved,
                )
            return True
        self._process_launch(command, scope, reachability, variables, delayed)
        return True

    @staticmethod
    def _option_value(words: tuple[str, ...], option: str) -> str:
        for index, word in enumerate(words):
            if word.casefold() == option and index + 1 < len(words):
                return words[index + 1]
        return ""

    @staticmethod
    def _is_process_command(name: str, command: BatchCmdCommand) -> bool:
        if name in _PROCESS_COMMANDS:
            return True
        if name in _NON_PROCESS_BUILTINS:
            return False
        return name.endswith((".exe", ".com", ".bat", ".cmd", ".vbs", ".js", ".ps1"))

    def _process_launch(
        self,
        command: BatchCmdCommand,
        scope: str,
        reachability: str,
        variables: dict[str, _ValueState],
        delayed: bool,
    ) -> None:
        target, states, unresolved = self._resolve_text(command.command, variables, delayed)
        arguments = []
        for word in command.words[1:]:
            resolved, more_states, more_unresolved = self._resolve_text(word, variables, delayed)
            arguments.append(resolved)
            states.extend(more_states)
            unresolved = unresolved or more_unresolved
        self._sink_operation(
            "process_launch", command, scope, reachability, target, states,
            {"arguments": arguments[:128], "command": target}, unresolved,
        )

    def _source_operation(
        self,
        kind: str,
        command: BatchCmdCommand,
        scope: str,
        reachability: str,
        target: str,
        action: str,
        unresolved: bool,
    ) -> _ValueState:
        value_id = _identity("val_", self.snapshot.content_sha256, scope, command.line, command.column, kind, len(self.operations))
        flow = _identity("flow_", self.snapshot.content_sha256, scope, command.line, command.column, kind, len(self.operations))
        index = self._append_operation(
            kind, command, scope, reachability, target, (), (value_id,), flow,
            {"action": action, "target": target},
            "partial" if unresolved or not target else "resolved",
            ("unresolved_target" if unresolved or not target else "",),
        )
        return _ValueState(value_id, "", flow, index)

    def _sink_operation(
        self,
        kind: str,
        command: BatchCmdCommand,
        scope: str,
        reachability: str,
        target: str,
        states: list[_ValueState],
        resolved_arguments: dict[str, object],
        unresolved: bool,
        *,
        output: bool = False,
    ) -> _ValueState:
        flow, ambiguous, source_draft, source_value = self._common_flow(states)
        limitations: list[str] = []
        if ambiguous:
            flow = ""
            source_draft = None
            source_value = ""
            unresolved = True
            limitations.append("ambiguous_source_flow")
        if unresolved:
            limitations.append("unresolved_input_or_target")
        input_values = tuple(dict.fromkeys(state.value_id for state in states if state.value_id))
        output_value = _identity("val_", self.snapshot.content_sha256, scope, command.line, command.column, kind, len(self.operations)) if output else ""
        index = self._append_operation(
            kind, command, scope, reachability, target, input_values,
            (output_value,) if output_value else (), flow,
            resolved_arguments,
            "partial" if unresolved or ambiguous or not target else "resolved",
            tuple(limitations),
        )
        if flow and source_value and index is not None:
            self._append_edge(_EdgeDraft(
                "source_to_sink", flow, source_value,
                output_value or _identity("val_", self.snapshot.content_sha256, "sink", index),
                source_draft, index,
            ))
        return _ValueState(output_value, "", flow, index)

    def _append_operation(
        self,
        kind: str,
        command: BatchCmdCommand,
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
        if len(self.operations) >= BATCH_CMD_MAX_OPERATIONS:
            self.limitations.add("operation_limit_exceeded")
            return None
        clean_limitations = tuple(item for item in limitations if item)
        self.operations.append(_OperationDraft(
            kind=kind,
            command=command,
            scope=scope,
            block="line:" + str(command.line),
            ordinal=self.ordinal,
            reachability=reachability,
            target=_bounded_text(target),
            input_values=input_values,
            output_values=output_values,
            flow_identity=flow_identity,
            resolved_arguments={key: value for key, value in resolved_arguments.items()},
            resolution=resolution,
            limitations=clean_limitations,
        ))
        self.ordinal += 1
        return len(self.operations) - 1

    def _append_edge(self, edge: _EdgeDraft) -> None:
        if len(self.edges) >= BATCH_CMD_MAX_FLOW_EDGES:
            self.limitations.add("flow_edge_limit_exceeded")
            return
        self.edges.append(edge)

    def _remember_unresolved(self, value: str) -> None:
        if len(self.unresolved) >= BATCH_CMD_MAX_UNRESOLVED:
            self.limitations.add("unresolved_construct_limit_exceeded")
            return
        self.unresolved.add(value[:512])

    def _finalize(self) -> StaticProgramAnalysis:
        scopes = tuple(sorted(self.commands_by_scope, key=lambda item: (item != self.module_scope, item)))
        function_ids = {
            scope: _identity("fn_", self.snapshot.content_sha256, "batch_scope", scope)
            for scope in scopes
        }
        actor_ids = {
            scope: _identity("spe_", self.snapshot.content_sha256, "batch_scope", scope)
            for scope in scopes
        }
        for draft in self.operations:
            draft.operation = StaticOperation.create(
                language="batch_cmd",
                operation_kind=draft.kind,
                source_location=StaticSourceLocation(
                    locator=static_artifact_identity(self.snapshot.content_sha256),
                    line=draft.command.line,
                    column=draft.command.column,
                    end_line=draft.command.end_line,
                    end_column=draft.command.end_column,
                ),
                enclosing_function_id=function_ids[draft.scope],
                basic_block_id=_identity(
                    "bb_", self.snapshot.content_sha256, draft.scope, draft.block,
                ),
                control_flow_ordinal=draft.ordinal,
                control_flow_provenance="static_control_flow",
                reachability_state=draft.reachability,
                platform="windows",
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
            "command_limit_exceeded", "flow_edge_limit_exceeded", "label_limit_exceeded",
            "operation_limit_exceeded", "unresolved_construct_limit_exceeded",
        })
        return StaticProgramAnalysis(
            content_sha256=self.snapshot.content_sha256,
            content_size=self.snapshot.size,
            artifact_identity=static_artifact_identity(self.snapshot.content_sha256),
            language="batch_cmd",
            language_version="windows_command_script_v1",
            parser_status="truncated" if limited else "complete",
            parser_schema_version=BATCH_CMD_FRONTEND_SCHEMA_VERSION,
            parser_digest=BATCH_CMD_FRONTEND_DIGEST,
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
        language="batch_cmd",
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
        language="batch_cmd",
        language_version="windows_command_script_v1",
        parser_status="truncated",
        parser_schema_version=BATCH_CMD_FRONTEND_SCHEMA_VERSION,
        parser_digest=BATCH_CMD_FRONTEND_DIGEST,
        operations=(),
        flow_edges=(),
        entrypoint_function_ids=(),
        unresolved_constructs=(),
        limitations=(limitation,),
        integrity_status="partial",
    )


def _decode_batch_source(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", "strict")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", "strict")
    if b"\x00" in raw:
        raise UnicodeDecodeError("utf-8", raw, 0, min(1, len(raw)), "batch_encoding_bom_required")
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return raw.decode("cp1252", "strict")


def analyze_batch_cmd_snapshot(snapshot: object) -> BatchCmdAnalysisResult:
    """Analyze one exact .bat/.cmd artifact through the canonical SQLite cache."""
    owned = require_artifact_read_snapshot(snapshot)
    if owned.extension.lower() not in {".bat", ".cmd"}:
        raise ValueError("batch_cmd_extension_not_applicable")
    if not owned.complete:
        return BatchCmdAnalysisResult(
            _unavailable(owned, owned.unavailable_reason or "artifact_read_unavailable"),
            "computed",
        )
    dependency = batch_cmd_analysis_dependency_digest()
    hit = scan_cache_repository().get_static_analysis(
        content_sha256=owned.content_sha256,
        analysis_dependency_digest=dependency,
    )
    if hit is not None:
        return BatchCmdAnalysisResult(hit.analysis, "sqlite_cache")
    if owned.size > BATCH_CMD_MAX_SOURCE_BYTES or owned.prefix_truncated:
        analysis = _truncated(owned, "source_size_limit_exceeded")
    else:
        raw = owned.read_prefix(owned.size)
        try:
            source = _decode_batch_source(raw)
            analysis = _Analyzer(owned, parse_batch_cmd(source)).analyze()
        except UnicodeDecodeError as exc:
            analysis = _unavailable(owned, "parser_failed:" + type(exc).__name__, status="failed")
        except (BatchCmdSyntaxError, TypeError, ValueError) as exc:
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
    return BatchCmdAnalysisResult(analysis, "computed")


__all__ = (
    "BATCH_CMD_FRONTEND_DIGEST",
    "BATCH_CMD_FRONTEND_SCHEMA_VERSION",
    "BATCH_CMD_MAX_SOURCE_BYTES",
    "BatchCmdAnalysisResult",
    "analyze_batch_cmd_snapshot",
    "batch_cmd_analysis_dependency_digest",
)
