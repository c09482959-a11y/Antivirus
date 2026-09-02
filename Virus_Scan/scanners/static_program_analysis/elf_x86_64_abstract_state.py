"""Bounded register/value abstract-state owner for decoded ELF64/x86-64 instructions."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scanners.static_program_analysis.elf_x86_64_disassembly import DecodedNativeProgram, DecodedInstruction

ELF_X86_64_ABSTRACT_STATE_SCHEMA_VERSION = "elf_x86_64_abstract_state_v1"
ELF_X86_64_ABSTRACT_STATE_MAX_PASSES = 16


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


ELF_X86_64_ABSTRACT_STATE_DIGEST = _digest({
    "schema": ELF_X86_64_ABSTRACT_STATE_SCHEMA_VERSION,
    "max_passes": ELF_X86_64_ABSTRACT_STATE_MAX_PASSES,
    "abi": "system_v_amd64",
    "syscall_abi": "linux_x86_64",
})


def _reg(value: str) -> str:
    name = value.strip().lower()
    if name in ("rax", "eax", "ax", "al", "ah"):
        return "rax"
    if name in ("rbx", "ebx", "bx", "bl", "bh"):
        return "rbx"
    if name in ("rcx", "ecx", "cx", "cl", "ch"):
        return "rcx"
    if name in ("rdx", "edx", "dx", "dl", "dh"):
        return "rdx"
    if name in ("rsi", "esi", "si", "sil"):
        return "rsi"
    if name in ("rdi", "edi", "di", "dil"):
        return "rdi"
    if name in ("rbp", "ebp", "bp", "bpl"):
        return "rbp"
    if name in ("rsp", "esp", "sp", "spl"):
        return "rsp"
    if name.startswith("r"):
        index_text = name[1:]
        for suffix in ("d", "w", "b"):
            if index_text.endswith(suffix):
                index_text = index_text[:-1]
                break
        if index_text.isdigit():
            index = int(index_text)
            if 8 <= index <= 15:
                return "r" + str(index)
    return ""



_CALLER_SAVED = frozenset({"rax","rcx","rdx","rsi","rdi","r8","r9","r10","r11"})


def _value_id(content_sha256: str, address: int, role: str) -> str:
    raw = json.dumps([content_sha256, address, role], separators=(",", ":")).encode()
    return "val_" + hashlib.sha256(raw).hexdigest()[:40]


@dataclass(frozen=True, slots=True)
class AbstractValue:
    value_id: str = ""
    constant: int | None = None
    producer_address: int | None = None

    def __post_init__(self) -> None:
        if type(self.value_id) is not str or type(self.constant) not in (int, type(None)) or type(self.producer_address) not in (int, type(None)):
            raise TypeError("native_abstract_value_invalid")
        if self.value_id and not self.value_id.startswith("val_"):
            raise ValueError("native_abstract_value_identity_invalid")


@dataclass(frozen=True, slots=True)
class AbstractInstructionState:
    address: int
    before: Mapping[str, AbstractValue]
    after: Mapping[str, AbstractValue]
    call_arguments: Mapping[str, AbstractValue]
    syscall_number: int | None
    syscall_arguments: Mapping[str, AbstractValue]


@dataclass(frozen=True, slots=True)
class NativeAbstractState:
    instruction_states: tuple[AbstractInstructionState, ...]
    limitations: tuple[str, ...]

    def for_address(self, address: int) -> AbstractInstructionState | None:
        for item in self.instruction_states:
            if item.address == address:
                return item
        return None


def _freeze_state(value: dict[str, AbstractValue]) -> Mapping[str, AbstractValue]:
    return MappingProxyType(dict(sorted(value.items())))


def _parse_operand_pair(text: str) -> tuple[str, str] | None:
    parts = tuple(part.strip().lower() for part in text.split(",", 1))
    return parts if len(parts) == 2 else None


def _integer(text: str) -> int | None:
    value = text.strip().lower()
    if not value:
        return None
    sign = ""
    if value[0] in {"+", "-"}:
        sign, value = value[0], value[1:]
    if not value:
        return None
    if value.startswith("0x"):
        digits = value[2:]
        if not digits or any(ch not in "0123456789abcdef" for ch in digits):
            return None
        return int(sign + value, 16)
    if not value.isdigit():
        return None
    return int(sign + value, 10)


def _merge(existing: dict[str, AbstractValue] | None, incoming: dict[str, AbstractValue]) -> tuple[dict[str, AbstractValue], bool]:
    if existing is None:
        return dict(incoming), True
    merged = {key: value for key, value in existing.items() if key in incoming and incoming[key] == value}
    return merged, merged != existing


def _apply_instruction(content_sha256: str, instruction: DecodedInstruction, state: dict[str, AbstractValue]) -> tuple[dict[str, AbstractValue], dict[str, AbstractValue], int | None, dict[str, AbstractValue]]:
    before = dict(state)
    call_args = {reg: before[reg] for reg in ("rdi","rsi","rdx","rcx","r8","r9") if reg in before}
    syscall_number = before.get("rax").constant if "rax" in before else None
    syscall_args = {reg: before[reg] for reg in ("rdi","rsi","rdx","r10","r8","r9") if reg in before}

    pair = _parse_operand_pair(instruction.operand_text)
    handled_writes: set[str] = set()
    if instruction.mnemonic == "mov" and pair is not None:
        dst, src = pair; dst_reg = _reg(dst); src_reg = _reg(src)
        if dst_reg:
            if src_reg and src_reg in state:
                state[dst_reg] = state[src_reg]
            elif (constant := _integer(src)) is not None:
                state[dst_reg] = AbstractValue(constant=constant)
            else:
                state.pop(dst_reg, None)
            handled_writes.add(dst_reg)
    elif instruction.mnemonic == "xor" and pair is not None:
        left, right = _reg(pair[0]), _reg(pair[1])
        if left and left == right:
            state[left] = AbstractValue(constant=0); handled_writes.add(left)

    if instruction.classification in {"call_direct", "call_indirect"}:
        for reg in _CALLER_SAVED:
            state.pop(reg, None)
        state["rax"] = AbstractValue(_value_id(content_sha256, instruction.address, "call_return"), producer_address=instruction.address)
        handled_writes.add("rax")
    elif instruction.classification == "syscall":
        # Linux syscall consumes RAX as the syscall number and returns through RAX.
        state.pop("rcx", None); state.pop("r11", None)
        state["rax"] = AbstractValue(_value_id(content_sha256, instruction.address, "syscall_return"), producer_address=instruction.address)
        handled_writes.update({"rax","rcx","r11"})

    for written in instruction.registers_written:
        canonical = _reg(written)
        if canonical and canonical not in handled_writes:
            state.pop(canonical, None)
    return before, call_args, syscall_number, syscall_args


def analyze_elf_x86_64_abstract_state(content_sha256: str, program: DecodedNativeProgram) -> NativeAbstractState:
    if type(content_sha256) is not str or len(content_sha256) != 64 or type(program) is not DecodedNativeProgram:
        raise TypeError("native_abstract_state_inputs_invalid")
    instructions = program.instruction_by_address()
    blocks: dict[int, list[DecodedInstruction]] = {}
    for item in program.instructions:
        blocks.setdefault(item.block_start, []).append(item)
    for values in blocks.values(): values.sort(key=lambda item: item.address)
    # A function entry owns an independent abstract-state root. Reachability is not
    # sufficient here: fallthrough blocks inherit state from their predecessor.
    entry_blocks = {
        item.block_start for item in program.instructions
        if item.block_start == item.function_entry
    }
    incoming: dict[int, dict[str, AbstractValue]] = {block: {} for block in entry_blocks}
    result_by_address: dict[int, AbstractInstructionState] = {}
    limitations: set[str] = set()
    changed = True; passes = 0
    while changed and passes < ELF_X86_64_ABSTRACT_STATE_MAX_PASSES:
        passes += 1; changed = False
        block_exit: dict[int, dict[str, AbstractValue]] = {}
        address_after: dict[int, dict[str, AbstractValue]] = {}
        for block in sorted(blocks):
            if block not in incoming:
                continue
            state = dict(incoming[block])
            for instruction in blocks[block]:
                before, call_args, syscall_number, syscall_args = _apply_instruction(content_sha256, instruction, state)
                result_by_address[instruction.address] = AbstractInstructionState(
                    instruction.address, _freeze_state(before), _freeze_state(dict(state)),
                    _freeze_state(call_args), syscall_number, _freeze_state(syscall_args),
                )
                address_after[instruction.address] = dict(state)
            block_exit[block] = dict(state)
        for edge in program.control_edges:
            if edge.target_address is None or edge.edge_kind == "call_direct":
                continue
            target_instruction = instructions.get(edge.target_address)
            if target_instruction is None:
                continue
            source_state = address_after.get(edge.source_address)
            if source_state is None:
                continue
            merged, did_change = _merge(incoming.get(target_instruction.block_start), source_state)
            if did_change:
                incoming[target_instruction.block_start] = merged; changed = True
    if changed:
        limitations.add("inter_basic_block_value_flow_not_interpreted")
    # Preserve deterministic entries even when a block had no propagated state.
    for instruction in program.instructions:
        if instruction.address not in result_by_address:
            result_by_address[instruction.address] = AbstractInstructionState(
                instruction.address, MappingProxyType({}), MappingProxyType({}), MappingProxyType({}), None, MappingProxyType({}),
            )
    return NativeAbstractState(tuple(result_by_address[address] for address in sorted(result_by_address)), tuple(sorted(limitations)))


__all__ = (
    "AbstractInstructionState", "AbstractValue", "ELF_X86_64_ABSTRACT_STATE_DIGEST",
    "ELF_X86_64_ABSTRACT_STATE_SCHEMA_VERSION", "NativeAbstractState", "analyze_elf_x86_64_abstract_state",
)
