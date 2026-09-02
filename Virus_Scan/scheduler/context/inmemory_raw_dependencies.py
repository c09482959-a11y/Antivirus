"""Explicit dependency ownership for in-memory raw scheduler execution."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, cast

from Virus_Scan.contracts.env_config import str_env
from Virus_Scan.scheduler.contracts.inmemory_raw import (
    FinalizeTagEvidenceGeneration,
    GlobalRawEligible,
    IntegrityTagApplicator,
    InMemoryRawScanDependencies,
    IssueRecorder,
    RawIdentity,
    RawStageJobBuilder,
    RawTagSequence,
    RememberScanEvidence,
    SchedulerThreadPoolFactory,
    StageJobExecutor,
)
from Virus_Scan.scheduler.ownership.raw_stage_jobs import RawStageJobBuildDependencies
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.api.thread_lifecycle import SchedulerThreadPool


@dataclass(frozen=True, slots=True)
class InMemoryRawDependencyInputs:
    deep_scan_thorough: Callable[[], bool]
    sniff_file_identity: Callable[[object], object]
    get_scan_extension: Callable[[object], str]
    runtime_value: Callable[..., object]
    normalize_stage: Callable[[object], str]
    choose_effective_stage: Callable[[object, object], object]
    global_raw_eligible: Callable[..., bool]
    global_raw_file_id: Callable[[object], str]
    build_raw_stage_jobs: Callable[..., object]
    raw_collector_cap: Callable[[str], int]
    raw_chunk_bytes: Callable[[], int]
    raw_queue_max_chunks: Callable[[], int]
    retry_max: Callable[[str], int]
    record_suppressed: Callable[..., object]
    yara_rules_state: Callable[[], object]
    yara_parallel_group_count: Callable[[object], int]
    execute_stage_job: Callable[..., object]
    record_issue: Callable[..., object]
    scanner_degraded_tags: Callable[..., object]
    finalize_tag_evidence_generation: Callable[..., object]
    normalize_tags: Callable[[object], object]
    staged_enrichment_score: Callable[..., object]
    set_scan_integrity: Callable[..., object]
    remember_scan_evidence: Callable[..., object]
    apply_integrity_tags: Callable[..., object]
    normalize_yara_hits: Callable[[object], object]
    log_error: Callable[[object], object]


def build_inmemory_raw_scan_dependencies(inputs: InMemoryRawDependencyInputs) -> InMemoryRawScanDependencies:
    """Build the immutable dependency boundary for in-memory raw execution."""

    return InMemoryRawScanDependencies(
        deep_scan_thorough=inputs.deep_scan_thorough,
        sniff_file_identity=cast("Callable[[object], RawIdentity]", inputs.sniff_file_identity),
        get_scan_extension=inputs.get_scan_extension,
        runtime_value=inputs.runtime_value,
        normalize_stage=inputs.normalize_stage,
        choose_effective_stage=inputs.choose_effective_stage,
        global_raw_eligible=cast("GlobalRawEligible", inputs.global_raw_eligible),
        global_raw_file_id=inputs.global_raw_file_id,
        build_raw_stage_jobs=cast("RawStageJobBuilder", inputs.build_raw_stage_jobs),
        raw_stage_job_build_dependencies=lambda: RawStageJobBuildDependencies(
            get_scan_extension=inputs.get_scan_extension,
            runtime_value=inputs.runtime_value,
            raw_collector_cap=inputs.raw_collector_cap,
            raw_chunk_bytes=inputs.raw_chunk_bytes,
            raw_queue_max_chunks=inputs.raw_queue_max_chunks,
            retry_max=inputs.retry_max,
            record_suppressed=inputs.record_suppressed,
            yara_rules_state=inputs.yara_rules_state,
            yara_parallel_group_count=inputs.yara_parallel_group_count,
            deep_scan_thorough=inputs.deep_scan_thorough,
        ),
        execute_stage_job=cast("StageJobExecutor", inputs.execute_stage_job),
        scheduler_thread_pool=cast("SchedulerThreadPoolFactory", SchedulerThreadPool),
        environ_get=str_env,
        record_issue=cast("IssueRecorder", inputs.record_issue),
        scanner_degraded_tags=cast("Callable[[], RawTagSequence]", inputs.scanner_degraded_tags),
        finalize_tag_evidence_generation=cast(
            "FinalizeTagEvidenceGeneration", inputs.finalize_tag_evidence_generation,
        ),
        normalize_tags=cast("Callable[[object], RawTagSequence]", inputs.normalize_tags),
        staged_enrichment_score=cast("Callable[[object, str, float], tuple[float, RawTagSequence]]", inputs.staged_enrichment_score),
        record_suppressed=inputs.record_suppressed,
        set_scan_integrity=inputs.set_scan_integrity,
        remember_scan_evidence=cast("RememberScanEvidence", inputs.remember_scan_evidence),
        apply_integrity_tags=cast("IntegrityTagApplicator", inputs.apply_integrity_tags),
        normalize_yara_hits=inputs.normalize_yara_hits,
        log_error=inputs.log_error,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        now=time.time,
    )
