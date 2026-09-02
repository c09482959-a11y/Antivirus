"""Bounded canonical .NET IL static-program-analysis frontend.

The frontend parses exact PE/CLI metadata and method bodies in-process. It never
loads an assembly, invokes a CLR, decompiles source, resolves live dependencies,
or executes managed/native code. Only exact metadata, IL control flow, literal
arguments, and bounded intra-basic-block value flows are projected into the
shared language-neutral static IR.
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
from Virus_Scan.scanners.static_program_analysis.dotnet_il_parser import (
    DOTNET_IL_MAX_SOURCE_BYTES,
    DOTNET_IL_PARSER_SCHEMA_VERSION,
    DotNetILInstruction,
    DotNetILMethod,
    DotNetILModule,
    DotNetILNotApplicable,
    DotNetILParseError,
    DotNetMethodReference,
    parse_dotnet_il,
)
from Virus_Scan.storage import scan_cache_repository

DOTNET_IL_FRONTEND_SCHEMA_VERSION = "dotnet_il_static_frontend_v2"
DOTNET_IL_MAX_OPERATIONS = 4_096
DOTNET_IL_MAX_FLOW_EDGES = 4_096
DOTNET_IL_MAX_UNRESOLVED = 256
DOTNET_IL_MAX_ARGUMENTS = 128
DOTNET_IL_MAX_TEXT = 4_096
_DOTNET_EXTENSIONS = frozenset((".dll", ".exe"))


def _digest_record(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    return hashlib.sha256(encoded).hexdigest()


def _identity(prefix: str, *parts: object) -> str:
    return prefix + _digest_record([str(part) for part in parts])[:40]


DOTNET_IL_FRONTEND_DIGEST = _digest_record({
    "frontend_schema": DOTNET_IL_FRONTEND_SCHEMA_VERSION,
    "ir_schema": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    "ir_schema_digest": STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    "limits": {
        "arguments": DOTNET_IL_MAX_ARGUMENTS,
        "flow_edges": DOTNET_IL_MAX_FLOW_EDGES,
        "operations": DOTNET_IL_MAX_OPERATIONS,
        "source_bytes": DOTNET_IL_MAX_SOURCE_BYTES,
        "unresolved": DOTNET_IL_MAX_UNRESOLVED,
    },
    "parser_schema": DOTNET_IL_PARSER_SCHEMA_VERSION,
    "value_flow": "bounded_intra_basic_block_stack_and_local_flow_v1",
})


def dotnet_il_analysis_dependency_digest() -> str:
    return DOTNET_IL_FRONTEND_DIGEST


@dataclass(frozen=True, slots=True)
class DotNetILAnalysisResult:
    analysis: StaticProgramAnalysis
    cache_source: str


@dataclass(frozen=True, slots=True)
class _AbstractValue:
    value_id: str
    literal: str = ""
    flow_identity: str = ""
    source_draft: int | None = None
    ambiguous: bool = False


@dataclass(frozen=True, slots=True)
class _CallMeaning:
    operation_kind: str
    role: str
    target_argument: int | None = None
    platform: str = ""


@dataclass(slots=True)
class _OperationDraft:
    method: DotNetILMethod
    instruction: DotNetILInstruction
    operation_kind: str
    ordinal: int
    reachability: str
    platform: str
    target: str
    input_value_ids: tuple[str, ...]
    output_value_ids: tuple[str, ...]
    flow_identity: str
    resolved_arguments: dict[str, object]
    resolution_state: str
    limitations: tuple[str, ...]
    operation: StaticOperation | None = None


@dataclass(frozen=True, slots=True)
class _EdgeDraft:
    edge_kind: str
    flow_identity: str
    source_value_id: str
    target_value_id: str
    source_draft: int | None
    target_draft: int | None
    resolution_state: str
    limitations: tuple[str, ...]


def _normalize_call(reference: DotNetMethodReference) -> tuple[str, str]:
    return reference.declaring_type.casefold(), reference.effective_name.casefold()


def _call_meaning(reference: DotNetMethodReference) -> _CallMeaning | None:
    owner, name = _normalize_call(reference)
    if reference.pinvoke_name:
        if name == "openprocess":
            return _CallMeaning("process_open", "standalone", target_argument=2, platform="windows")
        if name in {"virtualalloc", "virtualallocex", "ntallocatevirtualmemory"}:
            return _CallMeaning("memory_allocate", "standalone", target_argument=0, platform="windows")
        if name in {"readprocessmemory", "ntreadvirtualmemory", "minidumpwritedump"}:
            return _CallMeaning("memory_read", "standalone", target_argument=0, platform="windows")
        if name in {"writeprocessmemory", "ntwritevirtualmemory"}:
            return _CallMeaning("memory_write", "standalone", target_argument=0, platform="windows")
        if name in {"virtualprotect", "virtualprotectex", "ntprotectvirtualmemory"}:
            return _CallMeaning("memory_protect", "standalone", target_argument=0, platform="windows")
        if name in {"createthread", "createremotethread", "ntcreatethreadex"}:
            return _CallMeaning("thread_execute", "standalone", target_argument=0, platform="windows")
        if name in {"queueuserapc", "ntqueueapcthread"}:
            return _CallMeaning("apc_execute", "standalone", target_argument=0, platform="windows")
        if name in {"setthreadcontext", "wow64setthreadcontext"}:
            return _CallMeaning("context_execute", "standalone", target_argument=0, platform="windows")
        return None

    if owner == "system.io.file":
        if name in {"readallbytes", "readalltext", "readalllines", "openread"}:
            return _CallMeaning("file_read", "source", target_argument=0)
        if name in {"writeallbytes", "writealltext", "writealllines", "appendalltext", "openwrite"}:
            return _CallMeaning("file_write", "sink", target_argument=0)
        if name in {"open", "openhandle"}:
            return _CallMeaning("file_open", "standalone", target_argument=0)
    if owner in {"system.data.sqlite.sqliteconnection", "microsoft.data.sqlite.sqliteconnection"}:
        if name in {"open", "openasync"}:
            return _CallMeaning("database_open", "standalone")
    if owner in {
        "system.data.sqlite.sqlitecommand", "microsoft.data.sqlite.sqlitecommand",
        "system.data.common.dbcommand",
    } and name in {"executereader", "executereaderasync", "executescalar", "executenonquery"}:
        return _CallMeaning("database_query", "standalone")
    if owner.startswith("microsoft.win32.registry"):
        return _CallMeaning("registry_access", "standalone", platform="windows")
    if owner == "system.convert" and name in {"frombase64string", "fromhexstring"}:
        return _CallMeaning("decode", "transform")
    if owner in {
        "system.security.cryptography.protecteddata",
        "system.security.cryptography.aes",
        "system.security.cryptography.rsacryptoserviceprovider",
    } and name in {"unprotect", "decrypt", "decryptvalue"}:
        return _CallMeaning("decrypt", "transform", platform="windows" if "protecteddata" in owner else "")
    if owner in {
        "system.io.compression.gzipstream", "system.io.compression.deflatestream",
        "system.io.compression.brotlistream", "system.io.compression.zipfile",
    } and name in {"copyto", "copytoasync", "extracttofile", "extracttodirectory", "openread"}:
        return _CallMeaning("decompress", "transform")
    if owner in {
        "system.text.json.jsonserializer", "newtonsoft.json.jsonconvert",
        "system.runtime.serialization.formatters.binary.binaryformatter",
    } and name in {"serialize", "serializeobject"}:
        return _CallMeaning("serialize", "transform")
    if owner == "system.io.compression.zipfile" and name in {"createfromdirectory"}:
        return _CallMeaning("archive", "sink", target_argument=1)
    if owner in {"system.net.http.httpclient", "system.net.webclient"}:
        if name in {
            "getbytearrayasync", "getstringasync", "getstreamasync", "downloaddata",
            "downloaddatasync", "downloadstring", "downloadstringsync",
        }:
            return _CallMeaning("network_download", "source", target_argument=0)
        if name in {"postasync", "putasync", "sendasync", "uploadvalues", "uploaddata", "uploadstring"}:
            return _CallMeaning("network_send", "sink", target_argument=0)
    if owner in {"system.net.sockets.socket", "system.net.sockets.networkstream"} and name in {
        "send", "sendasync", "write", "writeasync",
    }:
        return _CallMeaning("network_send", "sink")
    if owner in {"system.net.sockets.socket", "system.net.http.httpclient"} and name in {
        "connect", "connectasync",
    }:
        return _CallMeaning("network_connect", "standalone", target_argument=0)
    if owner == "system.diagnostics.process" and name in {"start"}:
        return _CallMeaning("process_launch", "standalone", target_argument=0)
    return None


def _local_index(instruction: DotNetILInstruction) -> int | None:
    name = instruction.mnemonic
    if name.startswith("ldloc.") or name.startswith("stloc."):
        suffix = name.rsplit(".", 1)[-1]
        if suffix.isdigit():
            return int(suffix)
    if name in {"ldloc.s", "ldloc", "ldloca.s", "ldloca", "stloc.s", "stloc"}:
        return instruction.operand if type(instruction.operand) is int else None
    return None


def _unknown_value(content_sha256: str, method_token: int, offset: int, role: str) -> _AbstractValue:
    return _AbstractValue(_identity("val_", content_sha256, method_token, offset, role))


class _Analyzer:
    def __init__(self, snapshot: ArtifactReadSnapshot, module: DotNetILModule) -> None:
        self.snapshot = snapshot
        self.module = module
        self.references = module.reference_by_token()
        self.user_strings = module.user_string_by_token()
        self.methods = {method.token: method for method in module.methods}
        self.operations: list[_OperationDraft] = []
        self.edges: list[_EdgeDraft] = []
        self.unresolved = set(module.unresolved_constructs)
        self.limitations = set(module.limitations)
        self.truncated = False
        self.ordinal = 0
        self.method_reachability = self._method_reachability()

    def _remember_unresolved(self, value: str) -> None:
        if len(self.unresolved) >= DOTNET_IL_MAX_UNRESOLVED:
            self.limitations.add("unresolved_construct_limit_exceeded")
            self.truncated = True
            return
        self.unresolved.add(value[:512])

    def _method_reachability(self) -> dict[int, str]:
        state = {token: "locally_reachable" for token in self.methods}
        entry = self.module.entrypoint_token
        if entry not in self.methods:
            return state
        state[entry] = "entrypoint_reachable"
        pending = [entry]
        while pending:
            token = pending.pop()
            method = self.methods[token]
            source_state = state[token]
            for instruction in method.instructions:
                if instruction.offset not in method.reachable_offsets:
                    continue
                if instruction.operand_kind != "method" or type(instruction.operand) is not int:
                    continue
                target = instruction.operand
                if target not in self.methods:
                    continue
                target_state = (
                    "conditionally_reachable"
                    if source_state == "conditionally_reachable"
                    or instruction.offset in method.conditionally_reachable_offsets
                    else "entrypoint_reachable"
                )
                previous = state[target]
                if previous == "locally_reachable" or (
                    previous == "conditionally_reachable" and target_state == "entrypoint_reachable"
                ):
                    state[target] = target_state
                    pending.append(target)
        return state

    def _instruction_reachability(self, method: DotNetILMethod, instruction: DotNetILInstruction) -> str:
        if instruction.offset not in method.reachable_offsets:
            return "unreachable"
        method_state = self.method_reachability.get(method.token, "locally_reachable")
        if method_state == "locally_reachable":
            return method_state
        if method_state == "conditionally_reachable" or instruction.offset in method.conditionally_reachable_offsets:
            return "conditionally_reachable"
        return "entrypoint_reachable"

    @staticmethod
    def _block_start(method: DotNetILMethod, offset: int) -> int:
        selected = 0
        for candidate in method.basic_block_starts:
            if candidate > offset:
                break
            selected = candidate
        return selected

    def _append_operation(
        self,
        *,
        method: DotNetILMethod,
        instruction: DotNetILInstruction,
        reference: DotNetMethodReference,
        meaning: _CallMeaning,
        arguments: list[_AbstractValue],
        output_value: _AbstractValue | None,
        flow_identity: str,
        target: str,
        limitations: set[str],
    ) -> int | None:
        if len(self.operations) >= DOTNET_IL_MAX_OPERATIONS:
            self.limitations.add("operation_limit_exceeded")
            self.truncated = True
            return None
        literal_arguments = tuple(value.literal[:DOTNET_IL_MAX_TEXT] for value in arguments)
        if meaning.target_argument is not None and not target:
            limitations.add("target_argument_unresolved")
        resolution = "partial" if limitations else "resolved"
        resolved_arguments: dict[str, object] = {
            "arguments": literal_arguments,
            "call": reference.effective_name,
            "declaring_type": reference.declaring_type,
            "full_name": reference.full_name,
            "il_offset": instruction.offset,
            "method_token": method.token,
            "target": target[:DOTNET_IL_MAX_TEXT],
            "token": reference.token,
        }
        if reference.pinvoke_module:
            resolved_arguments["pinvoke_module"] = reference.pinvoke_module[:DOTNET_IL_MAX_TEXT]
        draft = _OperationDraft(
            method=method,
            instruction=instruction,
            operation_kind=meaning.operation_kind,
            ordinal=self.ordinal,
            reachability=self._instruction_reachability(method, instruction),
            platform=meaning.platform,
            target=target[:DOTNET_IL_MAX_TEXT],
            input_value_ids=tuple(value.value_id for value in arguments),
            output_value_ids=() if output_value is None else (output_value.value_id,),
            flow_identity=flow_identity,
            resolved_arguments=resolved_arguments,
            resolution_state=resolution,
            limitations=tuple(sorted(limitations)),
        )
        self.ordinal += 1
        self.operations.append(draft)
        return len(self.operations) - 1

    def _append_edge(
        self,
        *,
        edge_kind: str,
        value: _AbstractValue,
        target_draft: int | None,
        limitations: tuple[str, ...] = (),
    ) -> None:
        if not value.flow_identity or value.source_draft is None or target_draft is None:
            return
        if len(self.edges) >= DOTNET_IL_MAX_FLOW_EDGES:
            self.limitations.add("flow_edge_limit_exceeded")
            self.truncated = True
            return
        self.edges.append(_EdgeDraft(
            edge_kind=edge_kind,
            flow_identity=value.flow_identity,
            source_value_id=value.value_id,
            target_value_id=value.value_id,
            source_draft=value.source_draft,
            target_draft=target_draft,
            resolution_state="partial" if limitations else "resolved",
            limitations=limitations,
        ))

    def _call(
        self,
        method: DotNetILMethod,
        instruction: DotNetILInstruction,
        stack: list[_AbstractValue],
    ) -> None:
        token = instruction.operand if type(instruction.operand) is int else 0
        reference = self.references.get(token)
        if reference is None:
            self._remember_unresolved("method_token_unresolved:" + hex(token))
            stack.clear()
            return
        constructor = instruction.mnemonic == "newobj"
        required = reference.parameter_count + (0 if constructor else int(reference.has_this))
        underflow = max(0, required - len(stack))
        popped = [stack.pop() for _ in range(min(required, len(stack)))]
        popped.extend(
            _unknown_value(self.snapshot.content_sha256, method.token, instruction.offset, "missing_" + str(index))
            for index in range(underflow)
        )
        popped.reverse()
        arguments = popped[(0 if constructor or not reference.has_this else 1):]
        meaning = _call_meaning(reference)
        if meaning is None:
            if not reference.returns_void or constructor:
                stack.append(_unknown_value(self.snapshot.content_sha256, method.token, instruction.offset, "return"))
            return

        limitations: set[str] = set()
        if underflow:
            limitations.add("evaluation_stack_underflow")
        target = ""
        if meaning.target_argument is not None and meaning.target_argument < len(arguments):
            target = arguments[meaning.target_argument].literal
        flow_values = [value for value in arguments if value.flow_identity]
        unique_flows = {value.flow_identity for value in flow_values}
        if any(value.ambiguous for value in arguments) or len(unique_flows) > 1:
            limitations.add("ambiguous_input_flow")
        selected_flow = flow_values[0] if len(unique_flows) == 1 else None
        flow_identity = ""
        output_value: _AbstractValue | None = None
        returns_value = constructor or not reference.returns_void

        if meaning.role == "source":
            if reference.returns_void:
                limitations.add("call_signature_incompatible")
            else:
                flow_identity = _identity(
                    "flow_", self.snapshot.content_sha256, method.token, instruction.offset,
                    reference.full_name,
                )
                output_value = _AbstractValue(
                    value_id=_identity("val_", self.snapshot.content_sha256, method.token, instruction.offset, "source"),
                    flow_identity=flow_identity,
                )
        elif meaning.role == "transform":
            if reference.returns_void:
                limitations.add("call_signature_incompatible")
            else:
                flow_identity = "" if selected_flow is None else selected_flow.flow_identity
                output_value = _AbstractValue(
                    value_id=_identity("val_", self.snapshot.content_sha256, method.token, instruction.offset, "transform"),
                    flow_identity=flow_identity,
                    ambiguous=selected_flow is None and bool(flow_values),
                )
        elif returns_value:
            output_value = _unknown_value(self.snapshot.content_sha256, method.token, instruction.offset, "return")

        draft_index = self._append_operation(
            method=method,
            instruction=instruction,
            reference=reference,
            meaning=meaning,
            arguments=arguments,
            output_value=output_value,
            flow_identity=(selected_flow.flow_identity if meaning.role == "sink" and selected_flow else flow_identity),
            target=target,
            limitations=limitations,
        )
        if draft_index is not None and output_value is not None and meaning.role in {"source", "transform"}:
            output_value = _AbstractValue(
                value_id=output_value.value_id,
                literal=output_value.literal,
                flow_identity=output_value.flow_identity,
                source_draft=draft_index,
                ambiguous=output_value.ambiguous,
            )
        if meaning.role == "transform" and selected_flow is not None:
            self._append_edge(edge_kind="argument", value=selected_flow, target_draft=draft_index)
        elif meaning.role == "sink" and selected_flow is not None:
            self._append_edge(edge_kind="source_to_sink", value=selected_flow, target_draft=draft_index)
        if output_value is not None:
            stack.append(output_value)

    def _analyze_block(self, method: DotNetILMethod, instructions: tuple[DotNetILInstruction, ...]) -> None:
        stack: list[_AbstractValue] = []
        locals_by_index: dict[int, _AbstractValue] = {}
        for instruction in instructions:
            name = instruction.mnemonic
            if name == "ldstr":
                token = instruction.operand if type(instruction.operand) is int else 0
                value = self.user_strings.get(token)
                if value is None:
                    self._remember_unresolved("user_string_token_unresolved:" + hex(token))
                    stack.append(_unknown_value(self.snapshot.content_sha256, method.token, instruction.offset, "string"))
                else:
                    stack.append(_AbstractValue(
                        _identity("val_", self.snapshot.content_sha256, method.token, instruction.offset, "string"),
                        literal=value[:DOTNET_IL_MAX_TEXT],
                    ))
                continue
            if name == "ldnull":
                stack.append(_AbstractValue(
                    _identity("val_", self.snapshot.content_sha256, method.token, instruction.offset, name),
                    literal="null",
                ))
                continue
            if name.startswith("ldc.i4") or name == "ldc.i8":
                if name == "ldc.i4.m1":
                    literal = "-1"
                elif name.startswith("ldc.i4.") and name.rsplit(".", 1)[-1].isdigit():
                    literal = name.rsplit(".", 1)[-1]
                elif type(instruction.operand) is int:
                    literal = str(instruction.operand)
                else:
                    literal = ""
                stack.append(_AbstractValue(
                    _identity("val_", self.snapshot.content_sha256, method.token, instruction.offset, name),
                    literal=literal,
                ))
                continue
            if name.startswith("ldc.") or name.startswith("ldarg"):
                stack.append(_unknown_value(self.snapshot.content_sha256, method.token, instruction.offset, name))
                continue
            if name.startswith("ldloc"):
                index = _local_index(instruction)
                stack.append(
                    locals_by_index.get(index, _unknown_value(
                        self.snapshot.content_sha256, method.token, instruction.offset, "local",
                    ))
                )
                continue
            if name.startswith("stloc"):
                index = _local_index(instruction)
                value = stack.pop() if stack else _unknown_value(
                    self.snapshot.content_sha256, method.token, instruction.offset, "local_underflow",
                )
                if index is not None:
                    locals_by_index[index] = value
                continue
            if name == "dup":
                if stack:
                    stack.append(stack[-1])
                else:
                    self._remember_unresolved("evaluation_stack_underflow:dup")
                continue
            if name == "pop":
                if stack:
                    stack.pop()
                else:
                    self._remember_unresolved("evaluation_stack_underflow:pop")
                continue
            if name in {"call", "callvirt", "newobj"}:
                self._call(method, instruction, stack)
                continue
            if name in {"brtrue", "brtrue.s", "brfalse", "brfalse.s", "switch", "throw"}:
                if stack:
                    stack.pop()
                continue
            if name.startswith(("beq", "bne", "bge", "bgt", "ble", "blt")):
                if stack:
                    stack.pop()
                if stack:
                    stack.pop()
                continue
            if name == "ret":
                stack.clear()
                continue
            if name.startswith("starg"):
                if stack:
                    stack.pop()
                continue
            if name in {"box", "castclass", "isinst", "unbox.any"}:
                continue
            if name == "newarr":
                if stack:
                    stack.pop()
                stack.append(_unknown_value(self.snapshot.content_sha256, method.token, instruction.offset, name))
                continue
            if name in {"nop", "break", "volatile.", "tail.", "readonly.", "unaligned."}:
                continue
            self._remember_unresolved("stack_semantics_unresolved:" + name[:128])
            stack.clear()
            locals_by_index.clear()

    def analyze(self) -> StaticProgramAnalysis:
        for method in sorted(self.module.methods, key=lambda item: item.token):
            starts = method.basic_block_starts or (0,)
            instruction_tuple = method.instructions
            for index, start in enumerate(starts):
                end = starts[index + 1] if index + 1 < len(starts) else method.code_size
                block = tuple(item for item in instruction_tuple if start <= item.offset < end)
                if block:
                    self._analyze_block(method, block)
            if len(starts) > 1:
                self.limitations.add("inter_basic_block_value_flow_not_interpreted")
        return self._finalize()

    def _finalize(self) -> StaticProgramAnalysis:
        function_ids = {
            token: _identity("fn_", self.snapshot.content_sha256, token)
            for token in self.methods
        }
        actor_ids = {
            token: _identity("spe_", self.snapshot.content_sha256, token)
            for token in self.methods
        }
        for draft in self.operations:
            block_start = self._block_start(draft.method, draft.instruction.offset)
            draft.operation = StaticOperation.create(
                language="dotnet_il",
                operation_kind=draft.operation_kind,
                source_location=StaticSourceLocation(locator=static_artifact_identity(self.snapshot.content_sha256)),
                enclosing_function_id=function_ids[draft.method.token],
                basic_block_id=_identity(
                    "bb_", self.snapshot.content_sha256, draft.method.token, block_start,
                ),
                control_flow_ordinal=draft.ordinal,
                control_flow_provenance="static_control_flow",
                reachability_state=draft.reachability,
                platform=draft.platform,
                actor_program_entity=actor_ids[draft.method.token],
                target_resource_identity=(
                    _identity(
                        "res_", self.snapshot.content_sha256, draft.operation_kind, draft.target,
                    )
                    if draft.target else ""
                ),
                input_value_ids=draft.input_value_ids,
                output_value_ids=draft.output_value_ids,
                flow_identity=draft.flow_identity,
                resolved_arguments=draft.resolved_arguments,
                resolution_state=draft.resolution_state,
                limitations=draft.limitations,
                integrity_status="verified" if draft.resolution_state == "resolved" else "partial",
            )
        finalized_edges: list[StaticFlowEdge] = []
        for edge in self.edges:
            source = self.operations[edge.source_draft].operation if edge.source_draft is not None else None
            target = self.operations[edge.target_draft].operation if edge.target_draft is not None else None
            finalized_edges.append(StaticFlowEdge.create(
                flow_identity=edge.flow_identity,
                edge_kind=edge.edge_kind,
                source_value_id=edge.source_value_id,
                target_value_id=edge.target_value_id,
                source_operation_id="" if source is None else source.operation_id,
                target_operation_id="" if target is None else target.operation_id,
                resolution_state=edge.resolution_state,
                limitations=edge.limitations,
                integrity_status="verified" if edge.resolution_state == "resolved" else "partial",
            ))
        status = "truncated" if self.truncated else "partial" if self.module.limitations else "complete"
        entrypoints = (
            (function_ids[self.module.entrypoint_token],)
            if self.module.entrypoint_token in function_ids else ()
        )
        return StaticProgramAnalysis(
            content_sha256=self.snapshot.content_sha256,
            content_size=self.snapshot.size,
            artifact_identity=static_artifact_identity(self.snapshot.content_sha256),
            language="dotnet_il",
            language_version=self.module.runtime_version or "ecma_335",
            parser_status=status,
            parser_schema_version=DOTNET_IL_FRONTEND_SCHEMA_VERSION,
            parser_digest=DOTNET_IL_FRONTEND_DIGEST,
            operations=tuple(draft.operation for draft in self.operations if draft.operation is not None),
            flow_edges=tuple(finalized_edges),
            entrypoint_function_ids=entrypoints,
            unresolved_constructs=tuple(sorted(self.unresolved)),
            limitations=tuple(sorted(self.limitations)),
            integrity_status="partial" if status != "complete" else "verified",
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
        language="dotnet_il",
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
        language="dotnet_il",
        language_version="ecma_335",
        parser_status="truncated",
        parser_schema_version=DOTNET_IL_FRONTEND_SCHEMA_VERSION,
        parser_digest=DOTNET_IL_FRONTEND_DIGEST,
        operations=(),
        flow_edges=(),
        entrypoint_function_ids=(),
        unresolved_constructs=(),
        limitations=(limitation,),
        integrity_status="partial",
    )


def analyze_dotnet_il_snapshot(snapshot: object) -> DotNetILAnalysisResult:
    """Analyze one exact managed .dll/.exe through the canonical SQLite cache."""
    owned = require_artifact_read_snapshot(snapshot)
    if owned.extension.lower() not in _DOTNET_EXTENSIONS:
        raise ValueError("dotnet_il_extension_not_applicable")
    if not owned.complete:
        return DotNetILAnalysisResult(
            _unavailable(owned, owned.unavailable_reason or "artifact_read_unavailable"),
            "computed",
        )
    dependency = dotnet_il_analysis_dependency_digest()
    hit = scan_cache_repository().get_static_analysis(
        content_sha256=owned.content_sha256,
        analysis_dependency_digest=dependency,
    )
    if hit is not None:
        return DotNetILAnalysisResult(hit.analysis, "sqlite_cache")
    if owned.size > DOTNET_IL_MAX_SOURCE_BYTES or owned.prefix_truncated:
        analysis = _truncated(owned, "source_size_limit_exceeded")
    else:
        raw = owned.read_prefix(owned.size)
        try:
            analysis = _Analyzer(owned, parse_dotnet_il(raw)).analyze()
        except DotNetILNotApplicable as exc:
            analysis = _unavailable(owned, "managed_cli_not_applicable:" + str(exc))
        except (DotNetILParseError, TypeError, ValueError) as exc:
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
    return DotNetILAnalysisResult(analysis, "computed")


__all__ = (
    "DOTNET_IL_FRONTEND_DIGEST",
    "DOTNET_IL_FRONTEND_SCHEMA_VERSION",
    "DOTNET_IL_MAX_SOURCE_BYTES",
    "DotNetILAnalysisResult",
    "analyze_dotnet_il_snapshot",
    "dotnet_il_analysis_dependency_digest",
)
