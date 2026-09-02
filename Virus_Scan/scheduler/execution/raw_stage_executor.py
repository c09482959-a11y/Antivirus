"""Canonical raw-stage collector execution owner for scheduler execution phase."""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable, Protocol, TypeAlias

from Virus_Scan.scheduler.execution.raw_stage_collector_dispatch import dispatch_raw_stage_collector
from Virus_Scan.scheduler.execution.raw_stage_input import (
    build_raw_stage_input,
    normalise_raw_stage_out_tags,
    raw_stage_runtime_cache_max,
)

RawStageJob: TypeAlias = dict[str, object]
RawStageResult: TypeAlias = dict[str, object]
RawCollectorMapping: TypeAlias = Mapping[str, object]
RawCollectorValue: TypeAlias = object
RawStageCacheKey: TypeAlias = object


class RawStageRuntimeCacheState(Protocol):
    def raw_stage_cache_get(self, key: RawStageCacheKey) -> object: ...

    def configure_raw_stage_cache(self, *, max_entries: int) -> object: ...

    def raw_stage_cache_put(self, key: RawStageCacheKey, value: object) -> object: ...


@dataclass(frozen=True)
class RawStageExecutionDependencies:
    raw_chunk_bytes: Callable[[], int]
    raw_stage_cache_key: Callable[[RawStageJob], RawStageCacheKey]
    raw_stage_cache_allowed: Callable[[RawStageJob], bool]
    scheduler_runtime_state: Callable[[], RawStageRuntimeCacheState]
    make_json_safe: Callable[[object], object]
    record_suppressed: Callable[[str, BaseException], object]
    micro_stage_collect: Callable[..., RawCollectorValue]
    read_range_text: Callable[..., str]
    contextual_chunk_raw: Callable[..., RawCollectorValue]
    should_context_scan: Callable[[str], bool]
    decoded_chunk_tags: Callable[..., RawCollectorValue]
    should_decode_scan: Callable[[str], bool]
    explicit_missed_family_tag_scan: Callable[..., RawCollectorValue]
    pe_api_header: Callable[..., RawCollectorMapping]
    pe_api_chunk: Callable[..., RawCollectorMapping]
    pure_pe_header: Callable[..., RawCollectorMapping]
    contextual_tag_scan: Callable[..., RawCollectorValue]
    context_failure: Callable[..., RawCollectorValue]
    dotnet_header: Callable[..., RawCollectorMapping]
    scan_dotnet_file: Callable[..., RawCollectorValue]
    unity_dotnet_header: Callable[..., RawCollectorMapping]
    scan_unity_dotnet_layered_file: Callable[..., RawCollectorValue]
    unity_dotnet_chunk: Callable[..., RawCollectorMapping]
    extract_il_patterns: Callable[..., RawCollectorValue]
    analyze_il_pipeline: Callable[..., RawCollectorValue]
    record_issue: Callable[..., object]
    il2cpp_header: Callable[..., RawCollectorMapping]
    read_file_bytes: Callable[..., bytes]
    il2cpp_chunk: Callable[..., RawCollectorMapping]
    runtime_value: Callable[..., object]
    detect_unity_runtime_behavior: Callable[..., RawCollectorValue]
    byte_entropy: Callable[..., RawCollectorValue]
    bytecode_header: Callable[..., RawCollectorMapping]
    get_scan_extension: Callable[[object], str]
    detect_pickle_exec: Callable[..., RawCollectorValue]
    renpy_header: Callable[..., RawCollectorMapping]
    renpy_chunk: Callable[..., RawCollectorMapping]
    scan_rpgm_file: Callable[..., RawCollectorValue]
    rpgm_js_ast_header: Callable[..., RawCollectorMapping]
    rpgm_js_ast_chunk: Callable[..., RawCollectorMapping]
    js_execution_model_tags: Callable[..., RawCollectorValue]
    yara_rules_state: Callable[[], object]
    normalize_yara_hits: Callable[[object], object]
    yara_scan: Callable[..., RawCollectorValue]
    yara_scan_with_optional_zip: Callable[..., RawCollectorValue]
    raw_stage_failure_result: Callable[..., RawStageResult]
    normalize_raw_collector_value: Callable[[object], RawCollectorMapping]
    recoverable_exceptions: tuple[type[BaseException], ...]
    bytecode_chunk_request_factory: Callable[..., object]
    bytecode_chunk_request_owner: Callable[[object], RawCollectorMapping]
    contextual_chunk_request_factory: Callable[..., object]
    dotnet_chunk_request_owner: Callable[[object], RawCollectorMapping]
    pure_pe_chunk_request_owner: Callable[[object], RawCollectorMapping]


def execute_global_raw_stage_job(job: RawStageJob, *, deps: RawStageExecutionDependencies) -> RawStageResult:
    """Execute one raw queue stage.  No normalization/model writes here."""
    normalized = build_raw_stage_input(job, deps)
    out = normalized.out
    safe_job: RawStageJob = normalized.safe_job
    collector = str(safe_job["collector"])
    if normalized.boundary_failed and (not normalized.path or not collector):
        return deps.raw_stage_failure_result(
            out,
            collector or "raw_stage",
            RuntimeError("raw stage input rejected without caller hooks"),
            stage="raw_stage_input_rejected",
        )
    _cache_key = deps.raw_stage_cache_key(safe_job) if deps.raw_stage_cache_allowed(safe_job) else None
    if _cache_key is not None:
        try:
            cached = deps.scheduler_runtime_state().raw_stage_cache_get(_cache_key)
            if type(cached) is dict:
                clone = json.loads(json.dumps(deps.make_json_safe(cached), allow_nan=False))
                clone["raw_stage_cache_hit"] = True
                return clone
        except (TypeError, ValueError, RuntimeError) as _umige_suppressed_exc:
            deps.record_suppressed("raw_stage_exec_cache_read_failed", _umige_suppressed_exc)
    try:
        out = dispatch_raw_stage_collector(
            job=safe_job,
            path=normalized.path,
            collector=collector,
            start=normalized.start,
            size=normalized.size,
            out=out,
            deps=deps,
        )
        normalise_raw_stage_out_tags(out, deps)
    except (OSError, UnicodeError, RuntimeError, TypeError, ValueError, TimeoutError) as e:
        out = deps.raw_stage_failure_result(out, collector, e, stage="raw_stage_execute")
    except deps.recoverable_exceptions as e:
        deps.record_suppressed("raw_stage_unexpected_programmer_failure", e)
        raise
    try:
        if _cache_key is not None and not dict.get(out, "error"):
            deps.scheduler_runtime_state().configure_raw_stage_cache(max_entries=raw_stage_runtime_cache_max(deps))
            deps.scheduler_runtime_state().raw_stage_cache_put(_cache_key, json.loads(json.dumps(deps.make_json_safe(out), allow_nan=False)))
    except (TypeError, ValueError, RuntimeError) as _umige_suppressed_exc:
        deps.record_suppressed("raw_stage_exec_cache_store_failed", _umige_suppressed_exc)
    return out
