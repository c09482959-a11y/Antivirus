"""Raw-stage job admission and workload publication planning.

Batch 2 scheduler decomposition: raw-stage job intake, workload
classification, collector admission caps, and duplicate-limiting job identity
construction are scheduler queue-authority ownership.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_path_text, scheduler_text
from Virus_Scan.scheduler.ownership.raw_stage_job_admission import RawStageJobAdmissionState
from Virus_Scan.scheduler.ownership.raw_stage_job_planning import (
    add_raw_stage_chunk_jobs,
    add_raw_stage_file_jobs,
    add_raw_stage_yara_jobs,
    apply_raw_stage_job_cap,
    probe_raw_stage_file,
)


@dataclass(frozen=True)
class RawStageJobBuildDependencies:
    get_scan_extension: Callable[[object], str]
    runtime_value: Callable[..., object]
    raw_collector_cap: Callable[[str], int]
    raw_chunk_bytes: Callable[[], int]
    raw_queue_max_chunks: Callable[[], int]
    retry_max: Callable[[str], int]
    record_suppressed: Callable[[str, BaseException], object]
    yara_rules_state: Callable[[], object]
    yara_parallel_group_count: Callable[[object], int]
    deep_scan_thorough: Callable[[], bool]


def _raw_stage_jobs_no_hook_boundary_probe(path: object, collector: object, start: object) -> object:
    return (
        scheduler_path_text(path),
        scheduler_text(collector, unsupported_reason="raw_stage_collector_rejected"),
        scheduler_int(start, default=0, minimum=0, reason="raw_stage_job_start_rejected"),
    )


def build_raw_stage_jobs(path: object, file_id: str, effective_stage: str, ext_stage: str, identity: object, *, deps: RawStageJobBuildDependencies) -> list[dict[str, object]]:
    _ = (ext_stage, identity)  # retained RawStageJobBuilder contract context
    jobs: list[dict[str, object]] = []
    shape = probe_raw_stage_file(path, deps=deps)
    _ = _raw_stage_jobs_no_hook_boundary_probe(path, "identity", 0)
    job_state = RawStageJobAdmissionState(path=path, file_id=file_id, deps=deps, jobs=jobs)
    job_state.add("identity")
    add_raw_stage_chunk_jobs(job_state, shape=shape, effective_stage=effective_stage, deps=deps)
    add_raw_stage_file_jobs(job_state, shape=shape, effective_stage=effective_stage)
    add_raw_stage_yara_jobs(job_state, deps=deps)
    return apply_raw_stage_job_cap(jobs, ext=shape.ext, deps=deps)


__all__ = ("RawStageJobBuildDependencies", "build_raw_stage_jobs")
