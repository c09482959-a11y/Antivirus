"""Canonical bounded Linux ELF64/x86-64 semantic static-analysis frontend.

This module is the single public native-ELF lifecycle/cache owner. Internal
responsibilities are delegated to one canonical structure, symbol,
disassembly, abstract-state, semantic-operation, and data-flow owner each.
The frontend never claims runtime execution or ATT&CK authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from Virus_Scan.contracts.artifact_read_snapshot import ArtifactReadSnapshot, require_artifact_read_snapshot
from Virus_Scan.contracts.static_program_analysis import (
    STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    StaticProgramAnalysis,
    static_artifact_identity,
)
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_abstract_state import (
    ELF_X86_64_ABSTRACT_STATE_DIGEST,
    analyze_elf_x86_64_abstract_state,
)
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_dataflow import (
    ELF_X86_64_DATAFLOW_DIGEST,
    build_elf_x86_64_flow_edges,
)
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_disassembly import (
    ELF_X86_64_DISASSEMBLY_DIGEST,
    ELF_X86_64_MAX_BASIC_BLOCKS,
    ELF_X86_64_MAX_BRANCH_TARGETS,
    ELF_X86_64_MAX_DECODED_BYTES,
    ELF_X86_64_MAX_ELAPSED_SECONDS,
    ELF_X86_64_MAX_FLOW_EDGES,
    ELF_X86_64_MAX_FUNCTIONS,
    ELF_X86_64_MAX_INSTRUCTIONS,
    ELF_X86_64_MAX_OPERATIONS,
    ELF_X86_64_MAX_UNRESOLVED,
    decode_elf_x86_64,
)
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_semantics import (
    ELF_X86_64_SEMANTICS_DIGEST,
    build_elf_x86_64_semantic_operations,
)
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_structure import (
    ELF_X86_64_MAX_EXECUTABLE_SECTIONS,
    ELF_X86_64_MAX_PROGRAM_HEADERS,
    ELF_X86_64_MAX_SECTION_HEADERS,
    ELF_X86_64_STRUCTURE_DIGEST,
    NativeELFParseError,
    parse_elf_x86_64_structure,
)
from Virus_Scan.scanners.static_program_analysis.elf_x86_64_symbols import (
    ELF_X86_64_SYMBOLS_DIGEST,
    resolve_elf_x86_64_symbols,
)
from Virus_Scan.scanners.static_program_analysis.native_capstone_runtime import (
    PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY,
    NativeDecoderUnavailable,
    native_decoder_resource_state,
)
from Virus_Scan.storage import scan_cache_repository

NATIVE_ELF_X86_64_FRONTEND_SCHEMA_VERSION = "native_elf_x86_64_frontend_v3"
NATIVE_ELF_X86_64_MAX_SOURCE_BYTES = 10 * 1024 * 1024


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("utf-8", "strict")).hexdigest()


NATIVE_ELF_X86_64_FRONTEND_DIGEST = _canonical_digest({
    "components": {
        "structure": ELF_X86_64_STRUCTURE_DIGEST,
        "symbols": ELF_X86_64_SYMBOLS_DIGEST,
        "disassembly": ELF_X86_64_DISASSEMBLY_DIGEST,
        "abstract_state": ELF_X86_64_ABSTRACT_STATE_DIGEST,
        "semantics": ELF_X86_64_SEMANTICS_DIGEST,
        "dataflow": ELF_X86_64_DATAFLOW_DIGEST,
    },
    "decoder_dependency": PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY,
    "frontend_schema": NATIVE_ELF_X86_64_FRONTEND_SCHEMA_VERSION,
    "ir_schema": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    "ir_schema_digest": STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    "limits": {
        "basic_blocks": ELF_X86_64_MAX_BASIC_BLOCKS,
        "branch_targets": ELF_X86_64_MAX_BRANCH_TARGETS,
        "decoded_bytes": ELF_X86_64_MAX_DECODED_BYTES,
        "elapsed_seconds": ELF_X86_64_MAX_ELAPSED_SECONDS,
        "executable_sections": ELF_X86_64_MAX_EXECUTABLE_SECTIONS,
        "flow_edges": ELF_X86_64_MAX_FLOW_EDGES,
        "functions": ELF_X86_64_MAX_FUNCTIONS,
        "instructions": ELF_X86_64_MAX_INSTRUCTIONS,
        "operations": ELF_X86_64_MAX_OPERATIONS,
        "program_headers": ELF_X86_64_MAX_PROGRAM_HEADERS,
        "section_headers": ELF_X86_64_MAX_SECTION_HEADERS,
        "source_bytes": NATIVE_ELF_X86_64_MAX_SOURCE_BYTES,
        "unresolved_constructs": ELF_X86_64_MAX_UNRESOLVED,
    },
    "target": {
        "abi": "elf64_system_v_amd64", "architecture": "x86_64", "endianness": "little",
        "mode": "64", "operating_system": "linux", "syntax": "intel",
    },
})


def native_elf_x86_64_analysis_dependency_digest() -> str:
    return NATIVE_ELF_X86_64_FRONTEND_DIGEST


@dataclass(frozen=True, slots=True)
class NativeELFX86_64AnalysisResult:
    analysis: StaticProgramAnalysis
    cache_source: str


def _unavailable(snapshot: ArtifactReadSnapshot, reason: str, *, status: str = "unavailable") -> StaticProgramAnalysis:
    return StaticProgramAnalysis(
        content_sha256=snapshot.content_sha256,
        content_size=snapshot.size,
        artifact_identity=static_artifact_identity(snapshot.content_sha256),
        language="native_x86_64",
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


def _truncated(snapshot: ArtifactReadSnapshot, reason: str) -> StaticProgramAnalysis:
    return StaticProgramAnalysis(
        content_sha256=snapshot.content_sha256,
        content_size=snapshot.size,
        artifact_identity=static_artifact_identity(snapshot.content_sha256),
        language="native_x86_64",
        language_version="elf64_x86_64_system_v_amd64_v2",
        parser_status="truncated",
        parser_schema_version=NATIVE_ELF_X86_64_FRONTEND_SCHEMA_VERSION,
        parser_digest=NATIVE_ELF_X86_64_FRONTEND_DIGEST,
        operations=(),
        flow_edges=(),
        entrypoint_function_ids=(),
        unresolved_constructs=(),
        limitations=(reason,),
        integrity_status="partial",
    )


def _function_identity(content_sha256: str, address: int) -> str:
    raw = json.dumps([content_sha256, "native_x86_64", address], separators=(",", ":")).encode()
    return "fn_" + hashlib.sha256(raw).hexdigest()[:40]


def _analyze(snapshot: ArtifactReadSnapshot, raw: bytes) -> StaticProgramAnalysis:
    module = parse_elf_x86_64_structure(raw)
    symbols = resolve_elf_x86_64_symbols(raw, module)
    external_targets = frozenset(item.plt_address for item in symbols.plt_targets)
    program = decode_elf_x86_64(snapshot, raw, module, external_call_targets=external_targets)
    abstract_state = analyze_elf_x86_64_abstract_state(snapshot.content_sha256, program)
    operations = build_elf_x86_64_semantic_operations(snapshot, program, symbols, abstract_state)
    flow_edges = build_elf_x86_64_flow_edges(program, operations)
    limitations = tuple(sorted(set((*symbols.limitations, *program.limitations, *abstract_state.limitations))))
    unresolved = tuple(sorted(set(program.unresolved_constructs)))
    truncation_limits = frozenset({
        "basic_block_limit_exceeded", "branch_target_limit_exceeded", "decoded_byte_limit_exceeded",
        "elapsed_time_limit_exceeded", "flow_edge_limit_exceeded", "function_limit_exceeded",
        "instruction_limit_exceeded", "operation_limit_exceeded", "unresolved_construct_limit_exceeded",
        "inter_basic_block_value_flow_not_interpreted",
    })
    truncated = bool(truncation_limits & set(limitations))
    partial = bool(limitations or unresolved)
    parser_status = "truncated" if truncated else "partial" if partial else "complete"
    return StaticProgramAnalysis(
        content_sha256=snapshot.content_sha256,
        content_size=snapshot.size,
        artifact_identity=static_artifact_identity(snapshot.content_sha256),
        language="native_x86_64",
        language_version="elf64_x86_64_system_v_amd64_v2",
        parser_status=parser_status,
        parser_schema_version=NATIVE_ELF_X86_64_FRONTEND_SCHEMA_VERSION,
        parser_digest=NATIVE_ELF_X86_64_FRONTEND_DIGEST,
        operations=operations,
        flow_edges=flow_edges,
        entrypoint_function_ids=(_function_identity(snapshot.content_sha256, module.entrypoint),),
        unresolved_constructs=unresolved,
        limitations=limitations,
        integrity_status="partial" if partial else "verified",
    )


def analyze_native_elf_x86_64_snapshot(snapshot: object) -> NativeELFX86_64AnalysisResult:
    """Analyze one exact ELF64/x86-64 artifact through the canonical cache."""
    owned = require_artifact_read_snapshot(snapshot)
    if not owned.complete:
        return NativeELFX86_64AnalysisResult(_unavailable(owned, owned.unavailable_reason or "artifact_read_unavailable"), "computed")
    if owned.size < 4 or owned.read_prefix(4) != b"\x7fELF":
        raise ValueError("native_elf_magic_not_applicable")
    dependency = native_elf_x86_64_analysis_dependency_digest()
    hit = scan_cache_repository().get_static_analysis(content_sha256=owned.content_sha256, analysis_dependency_digest=dependency)
    if hit is not None:
        return NativeELFX86_64AnalysisResult(hit.analysis, "sqlite_cache")
    if owned.size > NATIVE_ELF_X86_64_MAX_SOURCE_BYTES or owned.prefix_truncated:
        analysis = _truncated(owned, "source_size_limit_exceeded")
    else:
        decoder_state = native_decoder_resource_state()
        if not decoder_state.available:
            analysis = _unavailable(owned, "native_decoder_unavailable:" + decoder_state.reason)
        else:
            raw = owned.read_prefix(owned.size)
            try:
                analysis = _analyze(owned, raw)
            except NativeELFParseError as exc:
                analysis = _unavailable(owned, "parser_failed:" + str(exc)[:320], status="failed")
            except NativeDecoderUnavailable as exc:
                analysis = _unavailable(owned, "native_decoder_unavailable:" + str(exc)[:320])
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                analysis = _unavailable(owned, "parser_failed:" + type(exc).__name__ + ":" + str(exc)[:320], status="failed")
    scan_cache_repository().put_static_analysis(
        content_sha256=owned.content_sha256,
        content_size=owned.size,
        analysis_dependency_digest=dependency,
        analysis=analysis,
    )
    return NativeELFX86_64AnalysisResult(analysis, "computed")


__all__ = (
    "NATIVE_ELF_X86_64_FRONTEND_DIGEST", "NATIVE_ELF_X86_64_FRONTEND_SCHEMA_VERSION",
    "NATIVE_ELF_X86_64_MAX_SOURCE_BYTES", "NativeELFParseError", "NativeELFX86_64AnalysisResult",
    "analyze_native_elf_x86_64_snapshot", "native_elf_x86_64_analysis_dependency_digest",
)
