"""Context-owned dependency factory for in-memory raw scanning.

The factory assembles immutable dependency snapshots only. Raw queue policy
helpers and raw stage execution dependency construction are bounded in sibling
context modules while this module preserves the existing explicit context-owned
raw dependency surface used by scheduler workers and tests.
"""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from typing import Mapping, TYPE_CHECKING

from Virus_Scan.scheduler.context.inmemory_raw_dependencies import InMemoryRawDependencyInputs, build_inmemory_raw_scan_dependencies
from Virus_Scan.scheduler.context.inmemory_raw_policy_dependencies import (
    decoded_chunk_tags_raw as _decoded_chunk_tags_raw,
    global_raw_eligible as _global_raw_eligible,
    global_raw_read_range_text as _global_raw_read_range_text,
    raw_chunk_bytes as _raw_chunk_bytes,
    raw_collector_cap as _raw_collector_cap,
    raw_queue_enabled as _raw_queue_enabled,
    raw_queue_max_chunks as _raw_queue_max_chunks,
    raw_queue_min_bytes as _raw_queue_min_bytes,
    raw_should_context_scan as _raw_should_context_scan,
    raw_should_decode_scan as _raw_should_decode_scan,
    raw_stage_job_build_dependencies as _raw_stage_job_build_dependencies,
    record_process_queue_suppressed as _record_process_queue_suppressed,
    record_raw_queue_issue as _record_raw_queue_issue,
    retry_max as _retry_max,
)
from Virus_Scan.scheduler.context.inmemory_raw_stage_dependencies import (
    RawStageExecutionDependencyRequest,
    raw_stage_execution_dependencies_from_request,
)
from Virus_Scan.scheduler.evidence.raw_collector_context import raw_collector_context_failure as _raw_collector_context_failure_impl
from Virus_Scan.scheduler.execution.raw_stage_executor import execute_global_raw_stage_job
from Virus_Scan.scheduler.ownership.raw_stage_jobs import build_raw_stage_jobs
from Virus_Scan.scheduler.queue.raw_integrity import apply_integrity_tags as _raw_apply_integrity_tags_impl
from Virus_Scan.scheduler.runtime.deep_scan_policy import scheduler_deep_scan_thorough
from Virus_Scan.scheduler.runtime.queue_filesystem import global_raw_file_id as _global_raw_file_id, raw_stage_cache_key as _raw_stage_cache_key, set_scan_integrity as _set_scan_integrity
from Virus_Scan.runtime.api import runtime_value
from Virus_Scan.runtime.api import log_error
from Virus_Scan.runtime.api import yara_rules_state
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.contracts.result_record import scanner_degraded_tags as _contract_scanner_degraded_tags
from Virus_Scan.routing.extensions import raw_stage_cache_allowed
from Virus_Scan.routing.magic import sniff_file_identity
from Virus_Scan.scanners.api.raw_chunk_contracts import DEFAULT_GLOBAL_RAW_DECODE_ANCHORS
from Virus_Scan.scanners.api.pickle_contracts import detect_python_pickle_opcode_exec
from Virus_Scan.detection.api.chains_contracts import evaluate_chain_evidence
from Virus_Scan.detection.api.tag_evidence_contracts import scoreable_tag_evidence
from Virus_Scan.detection.api.public_contracts import (
    contextual_tag_scan,
    explicit_missed_family_tag_scan,
    finalize_tag_evidence_generation,
    remember_scan_evidence as _remember_scan_evidence,
    scan_dotnet_file,
    staged_enrichment_score as _staged_enrichment_score,
    umige_js_execution_model_tags,
)
from Virus_Scan.scanners.api.binary_contracts import global_raw_pure_pe_header
from Virus_Scan.scanners.api.rpgm_contracts import scan_rpgm_file
from Virus_Scan.scanners.api.text_contracts import global_raw_pe_api_header
from Virus_Scan.utils.stages import choose_effective_stage, normalize_stage
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.yara.match import yara_scan, yara_scan_with_optional_zip
from Virus_Scan.yara.phase_contracts import yara_parallel_group_count
from Virus_Scan.yara.phase_contracts import normalize_yara_hits

if TYPE_CHECKING:
    from Virus_Scan.scheduler.contracts.inmemory_raw import InMemoryRawScanDependencies


_RAW_STAGE_EVIDENCE_KINDS = frozenset({"observed", "normalized", "derived", "composite"})


def score_inmemory_raw_stage_observations(
    tags: object, stage: object, base_score: object = 0.0,
) -> tuple[float, list[str]]:
    """Score one raw-stage observation bundle through canonical evidence owners."""
    tag_evidence = scoreable_tag_evidence(
        tags, allowed_evidence_kinds=_RAW_STAGE_EVIDENCE_KINDS,
    )
    chain_evidence = evaluate_chain_evidence(tags=tag_evidence)
    return _staged_enrichment_score(tag_evidence, chain_evidence, stage, base_score)


def execute_inmemory_raw_stage_job(job: dict[str, object]) -> dict[str, object]:
    return execute_global_raw_stage_job(
        job,
        deps=raw_stage_execution_dependencies_from_request(
            RawStageExecutionDependencyRequest(
                raw_chunk_bytes_func=_raw_chunk_bytes,
                raw_stage_cache_key_func=_raw_stage_cache_key,
                record_suppressed_func=_record_process_queue_suppressed,
                read_range_text_func=_global_raw_read_range_text,
                should_context_scan_func=_raw_should_context_scan,
                decoded_chunk_tags_func=_decoded_chunk_tags_raw,
                should_decode_scan_func=_raw_should_decode_scan,
                context_failure_func=_raw_collector_context_failure_impl,
                record_issue_func=_record_raw_queue_issue,
                detect_pickle_exec_func=detect_python_pickle_opcode_exec,
                yara_scan_func=yara_scan,
                yara_scan_with_optional_zip_func=yara_scan_with_optional_zip,
            )
        ),
    )


def inmemory_raw_scan_dependencies() -> InMemoryRawScanDependencies:
    def apply_integrity_tags_dependency(
        tags: object,
        integrity: object,
        marker: str = "raw_accumulator_incomplete",
    ) -> object:
        integrity_mapping: Mapping[str, object] | None = (
            scheduler_str_key_mapping_from_items(integrity.items())
            if isinstance(integrity, Mapping)
            else None
        )
        return _raw_apply_integrity_tags_impl(
            tags,
            integrity_mapping,
            marker=marker,
            scanner_degraded_tags=_contract_scanner_degraded_tags,
        )

    return build_inmemory_raw_scan_dependencies(InMemoryRawDependencyInputs(
        deep_scan_thorough=scheduler_deep_scan_thorough,
        sniff_file_identity=sniff_file_identity,
        get_scan_extension=get_scan_extension,
        runtime_value=runtime_value,
        normalize_stage=normalize_stage,
        choose_effective_stage=lambda ext_stage, identity: choose_effective_stage(
            ext_stage if type(ext_stage) is str else "",
            identity if isinstance(identity, Mapping) else {},
        ),
        global_raw_eligible=_global_raw_eligible,
        global_raw_file_id=_global_raw_file_id,
        build_raw_stage_jobs=build_raw_stage_jobs,
        raw_collector_cap=_raw_collector_cap,
        raw_chunk_bytes=_raw_chunk_bytes,
        raw_queue_max_chunks=_raw_queue_max_chunks,
        retry_max=_retry_max,
        record_suppressed=_record_process_queue_suppressed,
        yara_rules_state=yara_rules_state,
        yara_parallel_group_count=yara_parallel_group_count,
        execute_stage_job=execute_inmemory_raw_stage_job,
        record_issue=_record_raw_queue_issue,
        scanner_degraded_tags=_contract_scanner_degraded_tags,
        finalize_tag_evidence_generation=finalize_tag_evidence_generation,
        normalize_tags=normalize_tags,
        staged_enrichment_score=score_inmemory_raw_stage_observations,
        set_scan_integrity=_set_scan_integrity,
        remember_scan_evidence=_remember_scan_evidence,
        apply_integrity_tags=apply_integrity_tags_dependency,
        normalize_yara_hits=normalize_yara_hits,
        log_error=log_error,
    ))


__all__ = (
    "DEFAULT_GLOBAL_RAW_DECODE_ANCHORS",
    "_global_raw_eligible",
    "_global_raw_file_id",
    "_global_raw_read_range_text",
    "_raw_chunk_bytes",
    "_raw_collector_cap",
    "_raw_queue_enabled",
    "_raw_queue_max_chunks",
    "_raw_queue_min_bytes",
    "_raw_stage_cache_key",
    "_raw_stage_job_build_dependencies",
    "choose_effective_stage",
    "contextual_tag_scan",
    "detect_python_pickle_opcode_exec",
    "execute_inmemory_raw_stage_job",
    "explicit_missed_family_tag_scan",
    "finalize_tag_evidence_generation",
    "get_scan_extension",
    "global_raw_pe_api_header",
    "global_raw_pure_pe_header",
    "inmemory_raw_scan_dependencies",
    "normalize_stage",
    "raw_stage_cache_allowed",
    "runtime_value",
    "scan_dotnet_file",
    "scan_rpgm_file",
    "score_inmemory_raw_stage_observations",
    "sniff_file_identity",
    "umige_js_execution_model_tags",
    "yara_parallel_group_count",
    "yara_scan",
    "yara_scan_with_optional_zip",
)
