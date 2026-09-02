"""Context-owned raw stage execution dependency builder."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.context.inmemory_raw_policy_dependencies import (
    decoded_chunk_tags_raw,
    global_raw_read_range_text,
    raw_chunk_bytes,
    raw_should_context_scan,
    raw_should_decode_scan,
    record_process_queue_suppressed,
    record_raw_queue_issue,
)
from Virus_Scan.scheduler.evidence.raw_collector_context import raw_collector_context_failure as _raw_collector_context_failure_impl
from Virus_Scan.scheduler.execution.raw_stage_executor import RawStageExecutionDependencies, execute_global_raw_stage_job
from Virus_Scan.scheduler.execution.raw_stage_failure import raw_stage_failure_result as _raw_stage_failure_result_impl
from Virus_Scan.scheduler.execution.raw_work_executor import normalize_raw_collector_value
from Virus_Scan.scheduler.runtime.queue_filesystem import raw_stage_cache_key as _raw_stage_cache_key
from Virus_Scan.scheduler.runtime.queue_json import make_json_safe
from Virus_Scan.runtime.api import runtime_value
from Virus_Scan.runtime.api import detect_unity_runtime_behavior, read_file_bytes
from Virus_Scan.runtime.api import scheduler_runtime_state
from Virus_Scan.runtime.api import yara_rules_state
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.contracts.result_record import scanner_degraded_tags as _contract_scanner_degraded_tags
from Virus_Scan.routing.extensions import global_raw_bytecode_header, raw_stage_cache_allowed
from Virus_Scan.scanners.api.binary_contracts import global_raw_pure_pe_header
from Virus_Scan.scanners.api.dotnet_contracts import scan_unity_dotnet_layered_file
from Virus_Scan.scanners.api.entropy_contracts import byte_entropy
from Virus_Scan.scanners.api.il_pipeline_contracts import analyze_il_pipeline, extract_il_patterns
from Virus_Scan.scanners.api.pickle_contracts import detect_python_pickle_opcode_exec
from Virus_Scan.scanners.api.raw_chunk_request_contracts import BytecodeChunkRequest, ContextualRawChunkRequest, bytecode_chunk, dotnet_chunk, pure_pe_chunk
from Virus_Scan.scanners.api.raw_chunk_contracts import (
    dotnet_header as _scanner_dotnet_header,
    il2cpp_chunk as _scanner_il2cpp_chunk,
    il2cpp_header as _scanner_il2cpp_header,
    pe_api_chunk as _scanner_pe_api_chunk,
    unity_dotnet_chunk as _scanner_unity_dotnet_chunk,
    unity_dotnet_header as _scanner_unity_dotnet_header,
)
from Virus_Scan.scanners.api.renpy_contracts import global_raw_renpy_header
from Virus_Scan.scanners.api.rpgm_contracts import global_raw_rpgm_js_ast_header, scan_rpgm_file
from Virus_Scan.scanners.api.strings_contracts import intrastage_contextual_chunk_raw
from Virus_Scan.scanners.api.text_contracts import global_raw_pe_api_header, global_raw_renpy_chunk, global_raw_rpgm_js_ast_chunk
from Virus_Scan.detection.api.public_contracts import (
    contextual_tag_scan,
    explicit_missed_family_tag_scan,
    micro_stage_collect as _micro_stage_collect,
    scan_dotnet_file,
    umige_js_execution_model_tags,
)
from Virus_Scan.yara.match import yara_scan, yara_scan_with_optional_zip
from Virus_Scan.yara.phase_contracts import normalize_yara_hits


def raw_stage_failure_result(out: dict[str, object], collector: str, exc: BaseException, *, stage: str = "raw_stage_execute") -> dict[str, object]:
    return _raw_stage_failure_result_impl(out, collector, exc, stage=stage, scanner_degraded_tags=_contract_scanner_degraded_tags)


@dataclass(frozen=True, slots=True)
class RawStageExecutionDependencyRequest:
    """Internal collaborators for one raw-stage dependency snapshot."""

    raw_chunk_bytes_func: object = raw_chunk_bytes
    raw_stage_cache_key_func: object = _raw_stage_cache_key
    record_suppressed_func: object = record_process_queue_suppressed
    read_range_text_func: object = global_raw_read_range_text
    should_context_scan_func: object = raw_should_context_scan
    decoded_chunk_tags_func: object = decoded_chunk_tags_raw
    should_decode_scan_func: object = raw_should_decode_scan
    context_failure_func: object = _raw_collector_context_failure_impl
    record_issue_func: object = record_raw_queue_issue
    detect_pickle_exec_func: object = detect_python_pickle_opcode_exec
    yara_scan_func: object = yara_scan
    yara_scan_with_optional_zip_func: object = yara_scan_with_optional_zip


def raw_stage_execution_dependencies_from_request(
    request: RawStageExecutionDependencyRequest,
) -> RawStageExecutionDependencies:
    """Build one immutable raw-stage dependency snapshot."""
    return RawStageExecutionDependencies(
        raw_chunk_bytes=request.raw_chunk_bytes_func,
        raw_stage_cache_key=request.raw_stage_cache_key_func,
        raw_stage_cache_allowed=raw_stage_cache_allowed,
        scheduler_runtime_state=scheduler_runtime_state,
        make_json_safe=make_json_safe,
        record_suppressed=request.record_suppressed_func,
        micro_stage_collect=_micro_stage_collect,
        read_range_text=request.read_range_text_func,
        contextual_chunk_raw=intrastage_contextual_chunk_raw,
        should_context_scan=request.should_context_scan_func,
        decoded_chunk_tags=request.decoded_chunk_tags_func,
        should_decode_scan=request.should_decode_scan_func,
        explicit_missed_family_tag_scan=explicit_missed_family_tag_scan,
        pe_api_header=global_raw_pe_api_header,
        pe_api_chunk=_scanner_pe_api_chunk,
        pure_pe_header=global_raw_pure_pe_header,
        contextual_tag_scan=contextual_tag_scan,
        context_failure=request.context_failure_func,
        dotnet_header=_scanner_dotnet_header,
        scan_dotnet_file=scan_dotnet_file,
        unity_dotnet_header=_scanner_unity_dotnet_header,
        scan_unity_dotnet_layered_file=scan_unity_dotnet_layered_file,
        unity_dotnet_chunk=_scanner_unity_dotnet_chunk,
        extract_il_patterns=extract_il_patterns,
        analyze_il_pipeline=analyze_il_pipeline,
        record_issue=request.record_issue_func,
        il2cpp_header=_scanner_il2cpp_header,
        read_file_bytes=read_file_bytes,
        il2cpp_chunk=_scanner_il2cpp_chunk,
        runtime_value=runtime_value,
        detect_unity_runtime_behavior=detect_unity_runtime_behavior,
        byte_entropy=byte_entropy,
        bytecode_header=global_raw_bytecode_header,
        get_scan_extension=get_scan_extension,
        detect_pickle_exec=request.detect_pickle_exec_func,
        renpy_header=global_raw_renpy_header,
        renpy_chunk=global_raw_renpy_chunk,
        scan_rpgm_file=scan_rpgm_file,
        rpgm_js_ast_header=global_raw_rpgm_js_ast_header,
        rpgm_js_ast_chunk=global_raw_rpgm_js_ast_chunk,
        js_execution_model_tags=umige_js_execution_model_tags,
        yara_rules_state=yara_rules_state,
        normalize_yara_hits=normalize_yara_hits,
        yara_scan=request.yara_scan_func,
        yara_scan_with_optional_zip=request.yara_scan_with_optional_zip_func,
        raw_stage_failure_result=raw_stage_failure_result,
        normalize_raw_collector_value=normalize_raw_collector_value,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        bytecode_chunk_request_factory=BytecodeChunkRequest,
        bytecode_chunk_request_owner=bytecode_chunk,
        contextual_chunk_request_factory=ContextualRawChunkRequest,
        dotnet_chunk_request_owner=dotnet_chunk,
        pure_pe_chunk_request_owner=pure_pe_chunk,
    )



def execute_inmemory_raw_stage_job(job: dict[str, object]) -> dict[str, object]:
    return execute_global_raw_stage_job(
        job,
        deps=raw_stage_execution_dependencies_from_request(
            RawStageExecutionDependencyRequest()
        ),
    )


__all__ = (
    "execute_inmemory_raw_stage_job",
    "raw_stage_failure_result",
)
