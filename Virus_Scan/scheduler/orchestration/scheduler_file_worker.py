"""Canonical scheduler per-file worker construction and integrity projection."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TYPE_CHECKING

from Virus_Scan.contracts.artifact_read_snapshot import (
    attach_artifact_read_record,
    build_artifact_read_snapshot,
)
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.contracts.scan_session_snapshot import (
    ScanSessionSnapshot,
    attach_scan_session_record,
)
from Virus_Scan.scheduler.execution.scheduler_file_job_types import (
    SchedulerFileExecutionDependencies,
    SchedulerFileExecutionRequest,
)
from Virus_Scan.scheduler.execution.scheduler_file_cache import (
    execute_scheduler_file_with_cache,
)
from Virus_Scan.scheduler.internal.immutable_materialization import (
    materialize_scheduler_mapping_decision,
)

if TYPE_CHECKING:
    from Virus_Scan.routing.context_identity import RoutingEvidenceContext
    from Virus_Scan.scheduler.orchestration.scheduler_pipeline_dependencies import (
        SchedulerPipelineDependencies,
    )


@dataclass(frozen=True, slots=True)
class SchedulerFileResultIntegrityDecision:
    """Replayable decision for scheduler file-result integrity projection."""

    accepted: bool
    reason: str
    result_type: str
    integrity: dict[str, object]


@dataclass(frozen=True)
class SchedulerWorkerBuildRequest:
    """Immutable input required to build the scheduler file worker callback."""

    root: object
    compiled_rules: object
    per_file_timeout_sec: int | float
    slow_file_warn_sec: int | float
    strict: bool
    yara_enabled: bool
    routing_evidence_context: RoutingEvidenceContext | None
    scan_session_snapshot: ScanSessionSnapshot

    def __post_init__(self) -> None:
        if type(self.scan_session_snapshot) is not ScanSessionSnapshot:
            raise TypeError("scheduler_worker_scan_session_snapshot_required")


def scheduler_file_result_integrity_decision(
    result: object,
) -> SchedulerFileResultIntegrityDecision:
    """Return replayable scan-integrity projection evidence for one result."""

    result_type = no_hook_type_name(result)
    if type(result) is not dict:
        return SchedulerFileResultIntegrityDecision(
            False, "scheduler_file_result_not_mapping", result_type, {},
        )
    scan_integrity = dict.get(result, "scan_integrity")
    if scan_integrity is None:
        return SchedulerFileResultIntegrityDecision(
            False, "scheduler_file_result_scan_integrity_missing", result_type, {},
        )
    materialization = materialize_scheduler_mapping_decision(scan_integrity)
    if materialization.accepted and type(materialization.value) is dict:
        return SchedulerFileResultIntegrityDecision(
            True,
            "scheduler_file_result_scan_integrity_materialized",
            result_type,
            materialization.value,
        )
    evidence = materialization.value if type(materialization.value) is dict else {
        "scan_integrity_unavailable": True,
        "reason": materialization.reason,
        "evidence": materialization.evidence,
    }
    return SchedulerFileResultIntegrityDecision(
        False, materialization.reason, result_type, evidence,
    )


def build_scheduler_file_worker(
    *,
    request: SchedulerWorkerBuildRequest,
    dependencies: SchedulerPipelineDependencies,
    file_execution_dependencies: SchedulerFileExecutionDependencies,
) -> Callable[..., tuple[object, object]]:
    """Build the sole per-file scheduler worker callback."""

    def worker(
        path: object,
        previous_stage: str = "unknown",
        use_signal_timeout: bool = True,
    ) -> tuple[object, object]:
        started_file = dependencies.time()
        dependencies.clear_scan_integrity(path)
        artifact_read_snapshot = build_artifact_read_snapshot(path)
        executed_path, result = execute_scheduler_file_with_cache(
            request=SchedulerFileExecutionRequest(
                path=path,
                root=request.root,
                previous_stage=previous_stage,
                compiled_rules=request.compiled_rules,
                per_file_timeout_sec=request.per_file_timeout_sec,
                slow_file_warn_sec=request.slow_file_warn_sec,
                strict=request.strict,
                yara_enabled=request.yara_enabled,
                use_signal_timeout=use_signal_timeout,
                routing_evidence_context=request.routing_evidence_context,
                scan_session_snapshot=request.scan_session_snapshot,
                artifact_read_snapshot=artifact_read_snapshot,
            ),
            file_execution_dependencies=file_execution_dependencies,
            started_file=started_file,
        )
        attach_scan_session_record(result, request.scan_session_snapshot)
        integrity = scheduler_file_result_integrity_decision(result).integrity
        if integrity and type(result) is dict:
            result["scan_integrity"] = integrity
            dependencies.set_scan_integrity(executed_path, integrity)
        return executed_path, result

    return worker


__all__ = (
    "SchedulerFileResultIntegrityDecision",
    "SchedulerWorkerBuildRequest",
    "build_scheduler_file_worker",
    "scheduler_file_result_integrity_decision",
)
