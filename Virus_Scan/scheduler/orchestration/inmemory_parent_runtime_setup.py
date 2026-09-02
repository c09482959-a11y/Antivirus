"""In-memory long-lived scheduler parent runtime setup ownership."""
from __future__ import annotations

from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_contracts import (
    InMemoryParentRuntimeSetupRequest,
    InMemoryParentRuntimeSetupResult,
)
from Virus_Scan.scheduler.orchestration.inmemory_timeout_config_job_evidence import (
    attach_timeout_config_evidence_to_job_records,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_setup_values import (
    positive_process_count as _positive_process_count,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_setup_steps import (
    build_parent_runtime_bootstrap,
    build_parent_runtime_registry,
    start_parent_runtime_workers,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_result_steps import (
    build_parent_runtime_from_parts,
    log_parent_runtime_bootstrap,
)
from Virus_Scan.scheduler.runtime.multiprocessing_context import (
    get_scheduler_multiprocessing_context,
)
from Virus_Scan.scheduler.workers.result_contracts import (
    make_scheduler_worker_error_result,
)


def _attach_timeout_config_evidence_to_job_records(
    job_records: object,
    evidence_records: tuple[object, ...],
) -> None:
    attach_timeout_config_evidence_to_job_records(job_records, evidence_records)


def build_inmemory_parent_runtime(request: InMemoryParentRuntimeSetupRequest) -> InMemoryParentRuntimeSetupResult:
    bootstrap = build_parent_runtime_bootstrap(
        request,
        scheduler_context_factory=get_scheduler_multiprocessing_context,
    )
    registry = build_parent_runtime_registry(
        request,
        bootstrap,
        worker_error_result=make_scheduler_worker_error_result,
    )
    log_parent_runtime_bootstrap(request, bootstrap)
    start_parent_runtime_workers(bootstrap)
    return build_parent_runtime_from_parts(request, bootstrap, registry)


__all__ = ("build_inmemory_parent_runtime", "_positive_process_count")
