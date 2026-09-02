"""Context-owned raw queue policy dependency helpers.
This module owns runtime/config/scanner policy adapters used to construct
immutable in-memory raw scan dependency snapshots.  The public factory remains
thin and does not own raw queue policy calculations directly.
"""
from __future__ import annotations

import os

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS, RawRangeReadError
from Virus_Scan.scheduler.evidence.raw_queue_issue import record_raw_queue_issue as _record_raw_queue_issue_impl
from Virus_Scan.scheduler.evidence.scheduler_json_writer import (
    raw_chunk_bytes as _raw_chunk_bytes_impl,
    raw_queue_enabled as _raw_queue_enabled_impl,
    raw_queue_max_chunks as _raw_queue_max_chunks_impl,
    raw_queue_min_bytes as _raw_queue_min_bytes_impl,
)
from Virus_Scan.scheduler.evidence.suppressed_failures import record_process_queue_suppressed as _record_process_queue_suppressed_impl, record_raw_queue_suppressed as _record_raw_queue_suppressed_impl
from Virus_Scan.scheduler.ownership.raw_stage_eligibility import global_raw_eligible as _global_raw_eligible_impl
from Virus_Scan.scheduler.ownership.raw_stage_jobs import RawStageJobBuildDependencies
from Virus_Scan.scheduler.runtime.deep_scan_policy import scheduler_deep_scan_thorough
from Virus_Scan.scheduler.runtime.worker_capacity import raw_collector_cap as _raw_collector_cap_impl
from Virus_Scan.runtime.api import runtime_value
from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.runtime.api import yara_rules_state
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.scanners.api.raw_chunk_contracts import (
    DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS,
    DEFAULT_GLOBAL_RAW_DECODE_ANCHORS,
    decoded_chunk_tags as _decoded_chunk_tags_impl,
    read_range_text as _read_range_text_impl,
    should_context_scan as _raw_should_context_scan_impl,
    should_decode_scan as _raw_should_decode_scan_impl,
)
from Virus_Scan.utils.stages import normalize_stage
from Virus_Scan.yara.phase_contracts import yara_parallel_group_count
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_minimum_int, scheduler_path_text
from Virus_Scan.contracts.result_record import scanner_degraded_tags as _contract_scanner_degraded_tags
from Virus_Scan.scanners.api.payload_contracts import decoded_payload_tags
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from Virus_Scan.scheduler.context.inmemory_raw_policy_dependency_types import DecodedPayloadTagsFunc, RawDecodedTags, RawDecodeAnchors, RawIssueExtra, RawPolicyIssueRecorder, RuntimeValueReader, ScannerDegradedTagsFunc

def record_process_queue_suppressed(where: str, exc: BaseException, **kwargs: object) -> object:
    return _record_process_queue_suppressed_impl(where, exc, extra=kwargs.get("extra"))


def _raw_issue_extra(extra: object | None) -> RawIssueExtra:
    if extra is None:
        return None
    if type(extra) is dict:
        return dict.copy(extra)
    return {"raw_queue_issue_extra_rejected": True, "extra_type": no_hook_type_name(extra)}


def record_raw_queue_issue(where: str, exc: BaseException | str, *, fatal: bool = False, extra: object = None) -> object:
    _record_raw_queue_issue_impl(
        where,
        exc if isinstance(exc, BaseException) else RuntimeError(exc) if type(exc) is str else RuntimeError("raw_queue_issue_exception_rejected"),
        fatal=fatal,
        extra=_raw_issue_extra(extra),
        record_scheduler_suppressed=record_scheduler_suppressed,
        record_raw_suppressed=_record_raw_queue_suppressed_impl,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )
    return None


def _record_raw_policy_issue(where: str, exc: BaseException, *, extra: object = None) -> object:
    policy_extra = _raw_issue_extra(extra)
    merged_extra: dict[str, object] = {"policy_domain": "raw_queue"}
    if policy_extra is not None:
        merged_extra.update(policy_extra)
    return record_process_queue_suppressed(where, exc, extra=merged_extra)


def raw_chunk_bytes(default: int = 65536, *, runtime_value_reader: RuntimeValueReader = runtime_value, record_policy_issue: RawPolicyIssueRecorder = _record_raw_policy_issue) -> int:
    return _raw_chunk_bytes_impl(default=default, runtime_value=runtime_value_reader, record_suppressed=record_policy_issue)


def raw_queue_max_chunks(default: int = 192, *, runtime_value_reader: RuntimeValueReader = runtime_value, record_policy_issue: RawPolicyIssueRecorder = _record_raw_policy_issue) -> int:
    return _raw_queue_max_chunks_impl(default=default, runtime_value=runtime_value_reader, record_suppressed=record_policy_issue)


def raw_queue_enabled(*, runtime_value_reader: RuntimeValueReader = runtime_value, record_policy_issue: RawPolicyIssueRecorder = _record_raw_policy_issue) -> bool:
    return _raw_queue_enabled_impl(runtime_value=runtime_value_reader, record_suppressed=record_policy_issue)


def raw_queue_min_bytes(default: int = 0, *, runtime_value_reader: RuntimeValueReader = runtime_value, record_policy_issue: RawPolicyIssueRecorder = _record_raw_policy_issue) -> int:
    return _raw_queue_min_bytes_impl(default=default, runtime_value=runtime_value_reader, record_suppressed=record_policy_issue)


def raw_collector_cap(_collector: str = "") -> int:
    return _raw_collector_cap_impl(runtime_value=runtime_value)


def retry_max(_domain: str = "raw", *, runtime_value_reader: RuntimeValueReader = runtime_value, record_policy_issue: RawPolicyIssueRecorder = record_process_queue_suppressed) -> int:
    try:
        raw_value = runtime_value_reader("raw_retry_max", 1)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        record_policy_issue("raw_retry_max_unavailable", exc, extra={"policy_domain": "raw_queue", "field": "raw_retry_max"})
        raw_value = 1
    value, reason = scheduler_minimum_int(raw_value, minimum=1, reason="raw_retry_max_rejected")
    if reason:
        record_policy_issue("raw_retry_max_rejected", ValueError(reason), extra={"policy_domain": "raw_queue", "field": "raw_retry_max", "value_type": no_hook_type_name(raw_value)})
    return value


def global_raw_eligible(path: object, effective_stage: object | None = None) -> bool:
    def global_raw_path_size(path_value: object) -> int:
        path_text, path_reason = scheduler_path_text(path_value)
        if path_reason or path_text == "":
            raise OSError(path_reason or "raw_queue_path_missing")
        return os.path.getsize(path_text)

    return _global_raw_eligible_impl(
        path,
        effective_stage=effective_stage,
        raw_queue_enabled=raw_queue_enabled,
        raw_queue_min_bytes=raw_queue_min_bytes,
        get_size=global_raw_path_size,
        get_scan_extension=get_scan_extension,
        normalize_stage=normalize_stage,
        runtime_value=runtime_value,
    )


def raw_stage_job_build_dependencies() -> RawStageJobBuildDependencies:
    return RawStageJobBuildDependencies(
        get_scan_extension=get_scan_extension,
        runtime_value=runtime_value,
        raw_collector_cap=raw_collector_cap,
        raw_chunk_bytes=raw_chunk_bytes,
        raw_queue_max_chunks=raw_queue_max_chunks,
        retry_max=retry_max,
        record_suppressed=record_process_queue_suppressed,
        yara_rules_state=yara_rules_state,
        yara_parallel_group_count=yara_parallel_group_count,
        deep_scan_thorough=scheduler_deep_scan_thorough,
    )


def global_raw_read_range_text(path: object, start: int = 0, size: int | None = None, overlap: int = 0) -> str:
    del overlap  # Explicitly unused contract parameters.
    return _read_range_text_impl(
        path,
        start=start,
        size=size,
        default_size=raw_chunk_bytes(),
        range_error_cls=RawRangeReadError,
    )


def raw_should_context_scan(text: str) -> bool:
    return _raw_should_context_scan_impl(
        text,
        context_anchors=DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS,
        report=record_process_queue_suppressed,
    )


def raw_should_decode_scan(text: str) -> bool:
    return _raw_should_decode_scan_impl(
        text,
        decode_anchors=DEFAULT_GLOBAL_RAW_DECODE_ANCHORS,
        report=record_process_queue_suppressed,
    )


def decoded_chunk_tags_raw(
    chunk: str,
    path: object = None,
    offset: int = 0,
    *,
    decoded_payload_tags_func: DecodedPayloadTagsFunc = decoded_payload_tags,
    scanner_degraded_tags_func: ScannerDegradedTagsFunc = _contract_scanner_degraded_tags,
    report_issue: RawPolicyIssueRecorder = record_raw_queue_issue,
    decode_anchors: RawDecodeAnchors = DEFAULT_GLOBAL_RAW_DECODE_ANCHORS,
) -> RawDecodedTags:
    return _decoded_chunk_tags_impl(
        chunk,
        path=path,
        offset=offset,
        decoded_payload_tags=decoded_payload_tags_func,
        scanner_degraded_tags=scanner_degraded_tags_func,
        report=report_issue,
        decode_anchors=decode_anchors,
    )


__all__ = ("decoded_chunk_tags_raw", "global_raw_eligible", "global_raw_read_range_text", "raw_chunk_bytes", "raw_collector_cap", "raw_queue_enabled", "raw_queue_max_chunks", "raw_queue_min_bytes", "raw_should_context_scan", "raw_should_decode_scan", "raw_stage_job_build_dependencies", "record_process_queue_suppressed", "record_raw_queue_issue", "retry_max")
