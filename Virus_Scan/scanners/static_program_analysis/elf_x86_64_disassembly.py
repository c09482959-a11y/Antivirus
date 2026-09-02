"""Canonical packaged-Capstone instruction and control-flow owner for ELF64/x86-64."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
import time

from Virus_Scan.contracts.artifact_read_snapshot import ArtifactReadSnapshot
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_structure import ELFModule, ELFSection
from Virus_Scan.scanners.static_program_analysis.native_capstone_runtime import open_native_decoder

ELF_X86_64_DISASSEMBLY_SCHEMA_VERSION = "elf_x86_64_disassembly_v1"
ELF_X86_64_MAX_DECODED_BYTES = 1024 * 1024
ELF_X86_64_MAX_INSTRUCTIONS = 65_536
ELF_X86_64_MAX_BASIC_BLOCKS = 2_048
ELF_X86_64_MAX_OPERATIONS = 4_096
ELF_X86_64_MAX_FLOW_EDGES = 4_096
ELF_X86_64_MAX_UNRESOLVED = 256
ELF_X86_64_MAX_FUNCTIONS = 1_024
ELF_X86_64_MAX_BRANCH_TARGETS = 8_192
ELF_X86_64_MAX_ELAPSED_SECONDS = 3.0
ELF_X86_64_MAX_TEXT = 512


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


ELF_X86_64_DISASSEMBLY_DIGEST = _digest({
    "schema": ELF_X86_64_DISASSEMBLY_SCHEMA_VERSION,
    "limits": {
        "decoded_bytes": ELF_X86_64_MAX_DECODED_BYTES,
        "instructions": ELF_X86_64_MAX_INSTRUCTIONS,
        "basic_blocks": ELF_X86_64_MAX_BASIC_BLOCKS,
        "operations": ELF_X86_64_MAX_OPERATIONS,
        "flow_edges": ELF_X86_64_MAX_FLOW_EDGES,
        "unresolved": ELF_X86_64_MAX_UNRESOLVED,
        "functions": ELF_X86_64_MAX_FUNCTIONS,
        "branch_targets": ELF_X86_64_MAX_BRANCH_TARGETS,
        "elapsed_seconds": ELF_X86_64_MAX_ELAPSED_SECONDS,
    },
})


def _bounded(value: object) -> str:
    return str(value)[:ELF_X86_64_MAX_TEXT]


def _reachability_merge(previous: str | None, candidate: str) -> str:
    order = {"unresolved": 0, "unreachable": 1, "conditionally_reachable": 2, "locally_reachable": 3, "entrypoint_reachable": 4}
    if candidate not in order:
        return previous or "unresolved"
    if previous is None or order[candidate] > order.get(previous, -1):
        return candidate
    return previous


@dataclass(frozen=True, slots=True)
class DecodedInstruction:
    address: int
    file_offset: int
    size: int
    raw: bytes
    mnemonic: str
    operand_text: str
    groups: tuple[int, ...]
    registers_read: tuple[str, ...]
    registers_written: tuple[str, ...]
    immediate_target: int | None
    section: ELFSection
    block_start: int
    function_entry: int
    reachability: str
    classification: str

    @property
    def end(self) -> int:
        return self.address + self.size


@dataclass(frozen=True, slots=True)
class ControlEdgeDraft:
    edge_kind: str
    source_address: int
    target_address: int | None
    resolution_state: str
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DecodedNativeProgram:
    instructions: tuple[DecodedInstruction, ...]
    control_edges: tuple[ControlEdgeDraft, ...]
    operation_addresses: tuple[int, ...]
    limitations: tuple[str, ...]
    unresolved_constructs: tuple[str, ...]
    decoder_dependency_identity: str
    target_failures: tuple[tuple[int, str], ...]

    def instruction_by_address(self) -> dict[int, DecodedInstruction]:
        return {item.address: item for item in self.instructions}


class _Decoder:
    def __init__(self, snapshot: ArtifactReadSnapshot, raw: bytes, module: ELFModule, external_call_targets: frozenset[int]) -> None:
        self.snapshot = snapshot
        self.raw = raw
        self.module = module
        self.external_call_targets = external_call_targets
        self.runtime = open_native_decoder()
        binding = self.runtime.binding
        self.decoder = binding.Cs(binding.CS_ARCH_X86, binding.CS_MODE_64)
        self.decoder.detail = True
        self.decoder.syntax = binding.CS_OPT_SYNTAX_INTEL
        self.binding = binding
        self.instructions: dict[int, DecodedInstruction] = {}
        self.byte_owner: dict[int, int] = {}
        self.block_function: dict[int, int] = {}
        self.block_reachability: dict[int, str] = {}
        self.scheduled: set[int] = set()
        self.edges: list[ControlEdgeDraft] = []
        self.limitations: set[str] = set()
        self.unresolved: set[str] = set()
        self.control_target_failures: dict[int, str] = {}
        self.decoded_bytes = 0
        self.started = time.monotonic()

    def _add_unresolved(self, value: str) -> None:
        if len(self.unresolved) < ELF_X86_64_MAX_UNRESOLVED:
            self.unresolved.add(value)
        else:
            self.limitations.add("unresolved_construct_limit_exceeded")

    def _append_edge(self, edge: ControlEdgeDraft) -> None:
        if len(self.edges) < ELF_X86_64_MAX_FLOW_EDGES:
            self.edges.append(edge)
        else:
            self.limitations.add("flow_edge_limit_exceeded")

    def _within_time(self) -> bool:
        return time.monotonic() - self.started <= ELF_X86_64_MAX_ELAPSED_SECONDS

    def _schedule(self, address: int, function_entry: int, reachability: str, *, source_address: int | None = None) -> bool:
        reason = ""
        if len(self.scheduled) >= ELF_X86_64_MAX_BRANCH_TARGETS:
            reason = "branch_target_limit_exceeded"
        elif self.module.section_for_virtual_address(address) is None:
            reason = "control_flow_target_outside_executable_section"
        else:
            owner = self.byte_owner.get(address)
            if owner is not None and owner != address:
                reason = "control_flow_target_inside_instruction"
        if reason:
            self.limitations.add(reason)
            self._add_unresolved("target:" + hex(address))
            if source_address is not None: self.control_target_failures[source_address] = reason
            return False
        self.scheduled.add(address)
        self.block_function.setdefault(address, function_entry)
        self.block_reachability[address] = _reachability_merge(self.block_reachability.get(address), reachability)
        return True

    def _classify(self, mnemonic: str, groups: tuple[int, ...], immediate_target: int | None) -> str:
        owned = frozenset(groups)
        if self.binding.CS_GRP_RET in owned or self.binding.CS_GRP_IRET in owned: return "return"
        if mnemonic in {"syscall", "sysenter"}: return "syscall"
        if mnemonic in {"int", "int1", "int3", "ud2", "hlt"} or self.binding.CS_GRP_INT in owned: return "trap"
        if self.binding.CS_GRP_CALL in owned: return "call_direct" if immediate_target is not None else "call_indirect"
        if self.binding.CS_GRP_JUMP in owned:
            if immediate_target is None: return "branch_indirect"
            if mnemonic in {"jmp", "ljmp"}: return "branch_unconditional"
            return "branch_conditional"
        return "ordinary"

    def _decode_one(self, address: int, block_start: int, function_entry: int, reachability: str) -> DecodedInstruction | None:
        section = self.module.section_for_virtual_address(address)
        file_offset = self.module.file_offset(address)
        if section is None or file_offset is None: return None
        available = section.virtual_end - address
        if available <= 0: return None
        code = self.raw[file_offset:file_offset + min(available, 15)]
        decode_api_failed = False
        decoded = ()
        try:
            decoded = tuple(self.decoder.disasm(code, address, count=1))
        except self.binding.CsError:
            self.limitations.add("decoder_api_error")
            self._add_unresolved("instruction:" + hex(address))
            decode_api_failed = True
        if decode_api_failed:
            return None
        if len(decoded) != 1:
            self.limitations.add("undecodable_instruction"); self._add_unresolved("instruction:" + hex(address)); return None
        item = decoded[0]; size = int(item.size); raw_bytes = bytes(item.bytes)
        if size <= 0 or len(raw_bytes) != size or address + size > section.virtual_end:
            self.limitations.add("truncated_instruction"); self._add_unresolved("instruction:" + hex(address)); return None
        for byte_address in range(address, address + size):
            owner = self.byte_owner.get(byte_address)
            if owner is not None and owner != address:
                self.limitations.add("overlapping_instruction_candidate"); self._add_unresolved("instruction:" + hex(address)); return None
        for byte_address in range(address, address + size): self.byte_owner[byte_address] = address
        detail_api_failed = False
        operands = ()
        immediate_target = None
        read_raw = ()
        written_raw = ()
        try:
            operands = tuple(item.operands)
            immediate_target = int(operands[0].imm) if operands and operands[0].type == self.binding.x86.X86_OP_IMM else None
            read_raw, written_raw = item.regs_access()
        except self.binding.CsError:
            self.limitations.add("decoder_detail_error")
            self._add_unresolved("instruction:" + hex(address))
            detail_api_failed = True
        if detail_api_failed:
            return None
        mnemonic = _bounded(item.mnemonic).lower(); groups = tuple(sorted(int(group) for group in item.groups))
        instruction = DecodedInstruction(
            address, file_offset, size, raw_bytes, mnemonic, _bounded(item.op_str), groups,
            tuple(sorted(_bounded(item.reg_name(reg)) for reg in read_raw)),
            tuple(sorted(_bounded(item.reg_name(reg)) for reg in written_raw)), immediate_target,
            section, block_start, function_entry, reachability, self._classify(mnemonic, groups, immediate_target),
        )
        self.instructions[address] = instruction; self.decoded_bytes += size
        return instruction

    def _decode_block(self, start: int) -> None:
        function_entry = self.block_function[start]; reachability = self.block_reachability[start]
        address = start; previous_address: int | None = None
        while True:
            if not self._within_time(): self.limitations.add("elapsed_time_limit_exceeded"); return
            if len(self.instructions) >= ELF_X86_64_MAX_INSTRUCTIONS: self.limitations.add("instruction_limit_exceeded"); return
            if self.decoded_bytes >= ELF_X86_64_MAX_DECODED_BYTES: self.limitations.add("decoded_byte_limit_exceeded"); return
            if address != start and address in self.scheduled:
                if previous_address is not None: self._append_edge(ControlEdgeDraft("fallthrough", previous_address, address, "resolved", ()))
                return
            if address in self.instructions: return
            instruction = self._decode_one(address, start, function_entry, reachability)
            if instruction is None: return
            kind = instruction.classification; next_address = instruction.end
            if kind == "call_direct":
                target = instruction.immediate_target
                if target in self.external_call_targets:
                    # The call target is independently resolved by ELF relocation/symbol ownership.
                    pass
                else:
                    target_ok = target is not None and self._schedule(target, target, reachability, source_address=address)
                    if target_ok: self._append_edge(ControlEdgeDraft("call_direct", address, target, "resolved", ()))
                if self._schedule(next_address, function_entry, reachability): self._append_edge(ControlEdgeDraft("fallthrough", address, next_address, "resolved", ()))
                return
            if kind == "call_indirect":
                self._append_edge(ControlEdgeDraft("call_indirect", address, None, "unresolved", ("indirect_call_target_unresolved",)))
                self._add_unresolved("indirect_call:" + hex(address))
                if self._schedule(next_address, function_entry, reachability): self._append_edge(ControlEdgeDraft("fallthrough", address, next_address, "resolved", ()))
                return
            if kind == "branch_conditional":
                target = instruction.immediate_target
                if target is not None and self._schedule(target, function_entry, "conditionally_reachable", source_address=address): self._append_edge(ControlEdgeDraft("branch_conditional", address, target, "resolved", ()))
                if self._schedule(next_address, function_entry, reachability): self._append_edge(ControlEdgeDraft("fallthrough", address, next_address, "resolved", ()))
                return
            if kind == "branch_unconditional":
                target = instruction.immediate_target
                if target is not None and self._schedule(target, function_entry, reachability, source_address=address): self._append_edge(ControlEdgeDraft("branch_unconditional", address, target, "resolved", ()))
                return
            if kind == "branch_indirect":
                self._append_edge(ControlEdgeDraft("branch_indirect", address, None, "unresolved", ("indirect_branch_target_unresolved",)))
                self._add_unresolved("indirect_branch:" + hex(address)); return
            if kind == "return": self._append_edge(ControlEdgeDraft("control_return", address, None, "resolved", ())); return
            if kind == "trap": self._append_edge(ControlEdgeDraft("trap", address, None, "resolved", ())); return
            previous_address = address; address = next_address
            if self.module.section_for_virtual_address(address) is None:
                self.limitations.add("sequential_decode_left_executable_section"); return

    def run(self) -> DecodedNativeProgram:
        if self._schedule(self.module.entrypoint, self.module.entrypoint, "entrypoint_reachable"):
            pending: deque[int] = deque((self.module.entrypoint,))
        else:
            pending = deque()
        processed: set[int] = set()
        while pending or self.scheduled - processed:
            for address in sorted(self.scheduled - processed): pending.append(address)
            while pending:
                start = pending.popleft()
                if start in processed: continue
                if len(processed) >= ELF_X86_64_MAX_BASIC_BLOCKS: self.limitations.add("basic_block_limit_exceeded"); pending.clear(); break
                if len(set(self.block_function.values())) > ELF_X86_64_MAX_FUNCTIONS: self.limitations.add("function_limit_exceeded"); pending.clear(); break
                processed.add(start); self._decode_block(start)
                if not self._within_time(): pending.clear(); break
        for draft in self.edges:
            if draft.target_address is not None and draft.edge_kind in {"call_direct","branch_conditional","branch_unconditional","fallthrough"} and draft.target_address not in self.instructions:
                self.control_target_failures.setdefault(draft.source_address, "control_flow_target_operation_unavailable")
        operation_addresses = set(address for address in self.scheduled if address in self.instructions)
        operation_addresses.update(edge.source_address for edge in self.edges if edge.source_address in self.instructions)
        operation_addresses.update(item.address for item in self.instructions.values() if item.classification != "ordinary")
        ordered = tuple(sorted(operation_addresses))
        if len(ordered) > ELF_X86_64_MAX_OPERATIONS:
            self.limitations.add("operation_limit_exceeded"); ordered = ordered[:ELF_X86_64_MAX_OPERATIONS]
        return DecodedNativeProgram(
            tuple(self.instructions[address] for address in sorted(self.instructions)),
            tuple(self.edges), ordered, tuple(sorted(self.limitations)), tuple(sorted(self.unresolved)),
            self.runtime.identity.identity_digest, tuple(sorted(self.control_target_failures.items())),
        )


def decode_elf_x86_64(snapshot: ArtifactReadSnapshot, raw: bytes, module: ELFModule, *, external_call_targets: frozenset[int] = frozenset()) -> DecodedNativeProgram:
    if type(snapshot) is not ArtifactReadSnapshot or type(raw) is not bytes or type(module) is not ELFModule or type(external_call_targets) is not frozenset:
        raise TypeError("native_elf_disassembly_inputs_invalid")
    return _Decoder(snapshot, raw, module, external_call_targets).run()


__all__ = (
    "ControlEdgeDraft", "DecodedInstruction", "DecodedNativeProgram", "ELF_X86_64_DISASSEMBLY_DIGEST",
    "ELF_X86_64_DISASSEMBLY_SCHEMA_VERSION", "decode_elf_x86_64",
)
