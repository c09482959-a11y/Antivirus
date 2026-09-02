"""Canonical StaticFlowEdge construction owner for ELF64/x86-64 analysis."""
from __future__ import annotations

import hashlib
import json

from Virus_Scan.contracts.static_program_analysis import StaticFlowEdge, StaticOperation
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_disassembly import DecodedNativeProgram

ELF_X86_64_DATAFLOW_SCHEMA_VERSION = "elf_x86_64_dataflow_v1"
ELF_X86_64_DATAFLOW_MAX_EDGES = 4096


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


ELF_X86_64_DATAFLOW_DIGEST = _digest({"schema": ELF_X86_64_DATAFLOW_SCHEMA_VERSION, "max_edges": ELF_X86_64_DATAFLOW_MAX_EDGES})


def _flow_identity(source: StaticOperation, target: StaticOperation, value_id: str) -> str:
    raw = json.dumps([source.operation_id, target.operation_id, value_id], separators=(",", ":")).encode()
    return "flow_" + hashlib.sha256(raw).hexdigest()[:40]


def build_elf_x86_64_flow_edges(program: DecodedNativeProgram, operations: tuple[StaticOperation, ...]) -> tuple[StaticFlowEdge, ...]:
    if type(program) is not DecodedNativeProgram or type(operations) is not tuple or any(type(item) is not StaticOperation for item in operations):
        raise TypeError("native_elf_dataflow_inputs_invalid")
    by_address: dict[int, StaticOperation] = {}
    for operation in operations:
        address = operation.resolved_arguments.get("virtual_address")
        if type(address) is int:
            by_address[address] = operation
    edges: list[StaticFlowEdge] = []
    for draft in program.control_edges:
        source = by_address.get(draft.source_address)
        target = by_address.get(draft.target_address) if draft.target_address is not None else None
        if source is None:
            continue
        target_required = draft.edge_kind in {"call_direct","branch_conditional","branch_unconditional","fallthrough"}
        if target_required and target is None:
            continue
        edges.append(StaticFlowEdge.create(
            flow_identity="", edge_kind=draft.edge_kind, source_value_id="", target_value_id="",
            source_operation_id=source.operation_id, target_operation_id="" if target is None else target.operation_id,
            resolution_state=draft.resolution_state, limitations=draft.limitations,
            integrity_status="verified" if draft.resolution_state == "resolved" else "partial",
        ))
        if len(edges) >= ELF_X86_64_DATAFLOW_MAX_EDGES:
            return tuple(edges)
    # Value-flow authority is derived only from exact shared value identities established by abstract state.
    ordered = tuple(sorted(operations, key=lambda item: item.control_flow_ordinal))
    for source in ordered:
        if not source.output_value_ids:
            continue
        for target in ordered:
            if target.control_flow_ordinal <= source.control_flow_ordinal or target.enclosing_function_id != source.enclosing_function_id:
                continue
            shared = tuple(sorted(set(source.output_value_ids) & set(target.input_value_ids)))
            for value_id in shared:
                edges.append(StaticFlowEdge.create(
                    flow_identity=_flow_identity(source, target, value_id), edge_kind="source_to_sink",
                    source_value_id=value_id, target_value_id=value_id,
                    source_operation_id=source.operation_id, target_operation_id=target.operation_id,
                    resolution_state="resolved", limitations=(), integrity_status="verified",
                ))
                if len(edges) >= ELF_X86_64_DATAFLOW_MAX_EDGES:
                    return tuple(edges)
    return tuple(edges)


__all__ = (
    "ELF_X86_64_DATAFLOW_DIGEST", "ELF_X86_64_DATAFLOW_SCHEMA_VERSION", "build_elf_x86_64_flow_edges",
)
