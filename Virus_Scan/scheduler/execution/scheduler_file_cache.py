"""Canonical scheduler cache-admission boundary for one file execution."""
from __future__ import annotations

from Virus_Scan.contracts.artifact_read_snapshot import attach_artifact_read_record
from Virus_Scan.core.cache import pre_scan_cache_lookup
from Virus_Scan.scheduler.execution.scheduler_file_job import execute_scheduler_file_job
from Virus_Scan.scheduler.execution.scheduler_file_job_types import (
    SchedulerFileExecutionDependencies,
    SchedulerFileExecutionRequest,
)
from Virus_Scan.scheduler.execution.scheduler_yara_result import (
    cached_scheduler_yara_result,
)


def execute_scheduler_file_with_cache(
    *,
    request: SchedulerFileExecutionRequest,
    file_execution_dependencies: SchedulerFileExecutionDependencies,
    started_file: float | None = None,
) -> tuple[object, dict[str, object]]:
    """Execute one file through the canonical scheduler cache + semantic boundary.

    Scheduler mode is deliberately absent from this contract. Serial and
    process transports feed the same immutable request into this owner.
    """
    cache_started_file = (
        file_execution_dependencies.time()
        if started_file is None
        else float(started_file)
    )
    artifact_read_snapshot = request.artifact_read_snapshot
    cache_identity = request.scan_session_snapshot.cache_execution_identity
    cache_hit_result, _cache_sha256 = pre_scan_cache_lookup(
        artifact_read_snapshot,
        execution_identity=cache_identity,
    )
    if (
        type(cache_hit_result) is dict
        and cached_scheduler_yara_result(cache_hit_result, cache_identity) is not None
    ):
        active_timeout_budget = file_execution_dependencies.compute_timeout_budget(
            request.path,
            configured_timeout_seconds=request.per_file_timeout_sec,
            method="routing_triage",
            artifact_read_snapshot=request.artifact_read_snapshot,
        )
        elapsed_file = file_execution_dependencies.time() - cache_started_file
        cache_hit_result["scan_duration_seconds"] = round(elapsed_file, 6)
        cache_hit_result["timeout_evidence"] = active_timeout_budget.as_evidence()
        if request.slow_file_warn_sec and elapsed_file > request.slow_file_warn_sec:
            cache_hit_result["slow_file_seconds"] = round(elapsed_file, 3)
        attach_artifact_read_record(cache_hit_result, artifact_read_snapshot)
        return request.path, cache_hit_result
    return execute_scheduler_file_job(request, file_execution_dependencies)


__all__ = ("execute_scheduler_file_with_cache",)
