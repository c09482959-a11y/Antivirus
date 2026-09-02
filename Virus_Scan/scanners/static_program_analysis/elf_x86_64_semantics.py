"""Canonical imported-call/syscall to StaticOperation semantic owner for ELF64/x86-64."""
from __future__ import annotations

import hashlib
import json

from Virus_Scan.contracts.artifact_read_snapshot import ArtifactReadSnapshot
from Virus_Scan.contracts.static_program_analysis import StaticOperation, StaticSourceLocation, static_artifact_identity
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_abstract_state import NativeAbstractState, AbstractValue
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_disassembly import DecodedNativeProgram, DecodedInstruction
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_symbols import ELFSymbolResolution
from Virus_Scan.scanners.config import load_binary_policy_snapshot

ELF_X86_64_SEMANTICS_SCHEMA_VERSION = "elf_x86_64_semantics_v2"


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


_BINARY_POLICY = load_binary_policy_snapshot()
_IMPORT_SEMANTICS = _BINARY_POLICY.native_elf_import_semantics
_SYSCALL_SEMANTICS = _BINARY_POLICY.native_elf_syscall_semantics


def _import_semantic(symbol: str) -> str | None:
    normalized = symbol.casefold()
    for candidate, operation_kind in _IMPORT_SEMANTICS:
        if candidate == normalized:
            return operation_kind
    return None


def _syscall_semantic(number: int) -> tuple[str, str] | None:
    for candidate, name, operation_kind in _SYSCALL_SEMANTICS:
        if candidate == number:
            return name, operation_kind
    return None


ELF_X86_64_SEMANTICS_DIGEST = _digest({
    "schema": ELF_X86_64_SEMANTICS_SCHEMA_VERSION,
    "imports": _IMPORT_SEMANTICS,
    "syscalls": _SYSCALL_SEMANTICS,
})


def _identity(prefix: str, *parts: object) -> str:
    raw = json.dumps([str(part) for part in parts], separators=(",", ":")).encode()
    return prefix + hashlib.sha256(raw).hexdigest()[:40]


def _resource_identity(kind: str, value: AbstractValue | None) -> str:
    if value is None or value.constant is None:
        return ""
    if kind in {"file_read","file_write","network_send","network_download","network_connect"}:
        return _identity("res_", "linux_fd", value.constant)
    return ""


def _argument_record(values: object) -> dict[str, object]:
    if not hasattr(values, "items"):
        return {}
    out: dict[str, object] = {}
    for key, value in values.items():
        if type(value) is not AbstractValue:
            continue
        if value.value_id:
            out[str(key)] = {"value_id": value.value_id}
        elif value.constant is not None:
            out[str(key)] = {"constant": value.constant}
    return out


def _native_details(instruction: DecodedInstruction, decoder_identity: str) -> dict[str, object]:
    result: dict[str, object] = {
        "architecture": "x86_64", "decoder_dependency_identity": decoder_identity,
        "endianness": "little", "executable_region_identity": instruction.section.region_identity,
        "file_offset": instruction.file_offset, "groups": list(instruction.groups),
        "instruction_byte_sha256": hashlib.sha256(instruction.raw).hexdigest(),
        "instruction_length": instruction.size, "mnemonic": instruction.mnemonic,
        "mode": "64", "operand_text": instruction.operand_text,
        "registers_read": list(instruction.registers_read), "registers_written": list(instruction.registers_written),
        "section_identity": instruction.section.section_identity, "syntax": "intel", "virtual_address": instruction.address,
    }
    if instruction.immediate_target is not None:
        result["branch_target_virtual_address"] = instruction.immediate_target
    return result


def _semantic_kind(instruction: DecodedInstruction, symbols: ELFSymbolResolution, state: NativeAbstractState) -> tuple[str, str, str, tuple[str, ...], dict[str, object]]:
    """Return operation kind, resolution, target resource, limitations, semantic metadata."""
    instruction_state = state.for_address(instruction.address)
    metadata: dict[str, object] = {}
    target_resource = ""
    if instruction.classification == "call_direct":
        symbol = symbols.plt_symbol(instruction.immediate_target or -1)
        if symbol is not None:
            normalized = symbol.split("@", 1)[0].casefold()
            kind = _import_semantic(normalized)
            metadata["resolved_external_symbol"] = symbol
            metadata["resolved_call_identity"] = symbol + "@plt"
            if instruction_state is not None:
                metadata["call_arguments"] = _argument_record(instruction_state.call_arguments)
            if kind is not None:
                fd = instruction_state.call_arguments.get("rdi") if instruction_state is not None else None
                target_resource = _resource_identity(kind, fd)
                if kind in {"file_read", "file_write", "network_send", "network_download", "network_connect"} and not target_resource:
                    return kind, "partial", "", ("target_unresolved",), metadata
                return kind, "resolved", target_resource, (), metadata
            return "native_call", "partial", "", ("call_signature_incompatible",), metadata
        return "native_call", "resolved", "", (), metadata
    if instruction.classification == "call_indirect":
        return "native_call", "unresolved", "", ("indirect_call_target_unresolved",), metadata
    if instruction.classification == "syscall":
        number = instruction_state.syscall_number if instruction_state is not None else None
        if number is None:
            return "native_syscall", "unresolved", "", ("argument_unresolved",), metadata
        metadata["resolved_syscall_number"] = number
        semantic = _syscall_semantic(number)
        if semantic is None:
            return "native_syscall", "partial", "", ("call_signature_incompatible",), metadata
        name, kind = semantic
        metadata["resolved_syscall_name"] = name
        metadata["resolved_syscall_identity"] = f"linux_x86_64:{number}:{name}"
        if instruction_state is not None:
            metadata["syscall_arguments"] = _argument_record(instruction_state.syscall_arguments)
            fd = instruction_state.syscall_arguments.get("rdi")
        else:
            fd = None
        target_resource = _resource_identity(kind, fd)
        if kind in {"file_read", "file_write", "network_send", "network_download", "network_connect"} and not target_resource:
            return kind, "partial", "", ("target_unresolved",), metadata
        return kind, "resolved", target_resource, (), metadata
    if instruction.classification.startswith("branch_"):
        resolution = "unresolved" if instruction.classification == "branch_indirect" else "resolved"
        limitations = ("indirect_branch_target_unresolved",) if resolution == "unresolved" else ()
        return "native_branch", resolution, "", limitations, metadata
    if instruction.classification == "return": return "native_return", "resolved", "", (), metadata
    if instruction.classification == "trap": return "native_trap", "resolved", "", (), metadata
    return "native_instruction_boundary", "resolved", "", (), metadata


def build_elf_x86_64_semantic_operations(snapshot: ArtifactReadSnapshot, program: DecodedNativeProgram, symbols: ELFSymbolResolution, state: NativeAbstractState) -> tuple[StaticOperation, ...]:
    if type(snapshot) is not ArtifactReadSnapshot or type(program) is not DecodedNativeProgram or type(symbols) is not ELFSymbolResolution or type(state) is not NativeAbstractState:
        raise TypeError("native_elf_semantic_inputs_invalid")
    instructions = program.instruction_by_address(); operations: list[StaticOperation] = []
    for ordinal, address in enumerate(program.operation_addresses):
        instruction = instructions[address]
        kind, resolution, target_resource, limitations, semantic = _semantic_kind(instruction, symbols, state)
        target_failure = dict(program.target_failures).get(address)
        if target_failure is not None and instruction.classification in {"call_direct", "branch_conditional", "branch_unconditional"}:
            resolution = "unresolved"
            limitations = (target_failure,)
        instruction_state = state.for_address(address)
        input_ids: tuple[str, ...] = ()
        output_ids: tuple[str, ...] = ()
        if instruction_state is not None:
            source_values = instruction_state.syscall_arguments if instruction.classification == "syscall" else instruction_state.call_arguments if instruction.classification.startswith("call_") else {}
            input_ids = tuple(sorted({value.value_id for value in source_values.values() if value.value_id}))
            after_rax = instruction_state.after.get("rax")
            if kind in {"file_read","network_download","native_call","native_syscall"} and after_rax is not None and after_rax.value_id:
                output_ids = (after_rax.value_id,)
        details = _native_details(instruction, program.decoder_dependency_identity); details.update(semantic)
        function_id = _identity("fn_", snapshot.content_sha256, "native_x86_64", instruction.function_entry)
        operations.append(StaticOperation.create(
            language="native_x86_64", operation_kind=kind,
            source_location=StaticSourceLocation(locator=static_artifact_identity(snapshot.content_sha256)),
            enclosing_function_id=function_id,
            basic_block_id=_identity("bb_", snapshot.content_sha256, "native_x86_64", instruction.block_start),
            control_flow_ordinal=ordinal, control_flow_provenance="static_control_flow",
            reachability_state=instruction.reachability, platform="linux",
            actor_program_entity=_identity("spe_", snapshot.content_sha256, "native_x86_64", instruction.function_entry),
            target_resource_identity=target_resource, input_value_ids=input_ids, output_value_ids=output_ids,
            flow_identity="", resolved_arguments=details, resolution_state=resolution,
            limitations=limitations, integrity_status="verified" if resolution == "resolved" else "partial",
        ))
    return tuple(operations)


__all__ = (
    "ELF_X86_64_SEMANTICS_DIGEST", "ELF_X86_64_SEMANTICS_SCHEMA_VERSION", "build_elf_x86_64_semantic_operations",
)
