"""Timeout/retry maintenance orchestration for the in-memory scheduler parent."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import timeout_reporting_failure
from Virus_Scan.scheduler.workers.heartbeat import read_shared_heartbeat
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_error_detail
from Virus_Scan.scheduler.orchestration.inmemory_parent_timeout_maintenance_steps import (
    attach_parent_timeout_evidence,
    collect_parent_timeout_retry_evidence,
    run_timeout_sweep_for_parent,
)


@dataclass(frozen=True, slots=True)
class InMemoryTimeoutMaintenanceResult:
    """Immutable timeout-maintenance evidence emitted by parent orchestration."""

    timeout_retry_evidence: tuple[Mapping[str, object], ...] = ()
    timeout_reporting_failures: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "timeout_retry_evidence", immutable_tuple(self.timeout_retry_evidence))
        object.__setattr__(self, "timeout_reporting_failures", immutable_tuple(self.timeout_reporting_failures))


def run_inmemory_parent_timeout_maintenance(
    request: object,
    *,
    initial_retry_evidence_count: int | None = None,
    initial_cancel_evidence_count: int | None = None,
    read_heartbeat: object=read_shared_heartbeat,
) -> InMemoryTimeoutMaintenanceResult:
    """Run timeout/retry maintenance without mixing parent progress accounting."""

    if initial_retry_evidence_count is None:
        initial_retry_evidence_count = request.recovery.retry_evidence_count()
    if initial_cancel_evidence_count is None:
        initial_cancel_evidence_count = request.recovery.cancel_evidence_count()
    try:
        timeout_sweep_result = run_timeout_sweep_for_parent(
            request,
            read_heartbeat=read_heartbeat,
        )
        timeout_retry_evidence = collect_parent_timeout_retry_evidence(
            request,
            timeout_sweep_result=timeout_sweep_result,
            initial_retry_evidence_count=initial_retry_evidence_count,
            initial_cancel_evidence_count=initial_cancel_evidence_count,
        )
        attach_parent_timeout_evidence(request, timeout_retry_evidence)
        return InMemoryTimeoutMaintenanceResult(
            timeout_retry_evidence=timeout_retry_evidence,
            timeout_reporting_failures=tuple(timeout_sweep_result.timeout_reporting_failures),
        )
    except request.recoverable_exceptions as exc:
        log_error(str.__add__("in-memory timeout retry sweep failed: ", scheduler_error_detail(exc)))
        return InMemoryTimeoutMaintenanceResult(
            timeout_reporting_failures=(
                timeout_reporting_failure(
                    job_id="inmemory_parent_maintenance",
                    reason="timeout_retry_sweep_failed",
                    error=exc,
                ),
            ),
        )


__all__ = ("InMemoryTimeoutMaintenanceResult", "run_inmemory_parent_timeout_maintenance")
