"""Bounded scheduler runner orchestration steps."""
from __future__ import annotations

import logging
import signal

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import RuntimeEnvironmentOwner, record_scheduler_suppressed
from Virus_Scan.routing.context_identity import RoutingEvidenceContext
from Virus_Scan.scheduler.runtime.child_console import install_child_console_handlers
from Virus_Scan.scheduler.orchestration.scheduler_target_planning import SchedulerTargetPlanningRequest
from Virus_Scan.scheduler.orchestration.scheduler_mode_contracts import SchedulerModeDispatchDependencies, SchedulerModeDispatchRequest
from Virus_Scan.scheduler.orchestration.scheduler_runner_support import resolve_scheduler_pipeline_controls
from Virus_Scan.scheduler.orchestration.finalization import SchedulerPipelineFinalizationDependencies, SchedulerPipelineFinalizationRequest
from Virus_Scan.scheduler.orchestration.scheduler_pipeline_profile_finalization import SchedulerPipelineRunFinalizationRequest, SchedulerProfilePolicyRequest, configure_scheduler_profile_policy, finalize_scheduler_pipeline_run
from Virus_Scan.scheduler.orchestration.scheduler_file_worker import SchedulerWorkerBuildRequest, build_scheduler_file_worker
from Virus_Scan.scheduler.orchestration.scheduler_pipeline_runtime import SchedulerPipelineRunState, build_partial_result_writer, maybe_install_queue_child_console_handlers


def prepare_scheduler_runner_controls(
    *,
    deps: object,
    scheduler_runtime: object,
    scheduler_input: object,
    strict: object,
    defer_profile_flush: object,
    freeze_existing_baselines: object,
    yara_enabled: object,
    profile_flush_every: object,
    bulk_profile_flush_every: object,
) -> tuple[object, object]:
    """Resolve scheduler controls and configure runtime profile policy."""
    controls = resolve_scheduler_pipeline_controls(
        scheduler=scheduler_input,
        strict=strict,
        defer_profile_flush=defer_profile_flush,
        freeze_existing_baselines=freeze_existing_baselines,
        yara_enabled=yara_enabled,
    )
    profile_policy_snapshot = configure_scheduler_profile_policy(
        SchedulerProfilePolicyRequest(
            scheduler_runtime=scheduler_runtime,
            dependencies=deps,
            defer_profile_flush=controls.defer_profile_flush,
            freeze_existing_baselines=controls.freeze_existing_baselines,
            profile_flush_every=profile_flush_every,
            bulk_profile_flush_every=bulk_profile_flush_every,
        )
    )
    maybe_install_queue_child_console_handlers(
        scheduler_requested=controls.scheduler_requested,
        runtime_environment_owner_factory=RuntimeEnvironmentOwner,
        signal_module=signal,
        install_handlers=install_child_console_handlers,
        record_suppressed=record_scheduler_suppressed,
    )
    return controls, profile_policy_snapshot


def plan_scheduler_runner_targets(*, deps: object, root: object, file_list_path: object, max_files: object, scheduler_requested: object) -> object:
    """Plan scheduler targets with explicit logging dependencies."""
    return deps.plan_scheduler_targets(
        SchedulerTargetPlanningRequest(
            root=root,
            file_list_path=file_list_path,
            max_files=max_files,
            scheduler_requested=scheduler_requested,
        ),
        log_error=deps.log_error,
        logging_module=logging,
    )


def build_scheduler_file_worker_execution(
    *,
    deps: object,
    root: object,
    compiled_rules: object,
    per_file_timeout_sec: object,
    slow_file_warn_sec: object,
    strict_value: object,
    yara_enabled_value: object,
    partial_output_path: object,
    partial_output_every: object,
    total_files: int,
    scan_session_snapshot: object,
) -> tuple[object, object, object]:
    """Build state, partial writer, and per-file worker for the runner."""
    state = SchedulerPipelineRunState(results={})
    write_partial = build_partial_result_writer(
        state=state,
        dependencies=deps,
        partial_output_path=partial_output_path,
        total_files=total_files,
        partial_output_every=partial_output_every,
    )
    worker = build_scheduler_file_worker(
        request=SchedulerWorkerBuildRequest(
            root=root,
            compiled_rules=compiled_rules,
            per_file_timeout_sec=per_file_timeout_sec,
            slow_file_warn_sec=slow_file_warn_sec,
            strict=strict_value,
            yara_enabled=yara_enabled_value,
            routing_evidence_context=RoutingEvidenceContext.build(root),
            scan_session_snapshot=scan_session_snapshot,
        ),
        dependencies=deps,
        file_execution_dependencies=deps.build_scheduler_file_execution_dependencies(),
    )
    return state, write_partial, worker


def run_scheduler_mode_dispatch(
    *,
    deps: object,
    state_results: object,
    scheduler_requested: object,
    worker: object,
    result_retainer: object,
    derived_cache_writer: object,
    write_partial: object,
    root: object,
    all_files: tuple[object, ...],
    total_files: int,
    max_workers: object,
    strict_value: object,
    yara_enabled_value: object,
    progress_every: object,
    throttle_sec: object,
    partial_output_path: object,
    partial_output_every: object,
    slow_file_warn_sec: object,
    per_file_timeout_sec: object,
    work_queue_dir: object,
    worker_output_path: object,
    scan_session_snapshot: object,
) -> object:
    """Dispatch scheduler mode with immutable run inputs."""
    return deps.run_scheduler_mode(
        SchedulerModeDispatchRequest(
            scheduler=scheduler_requested,
            workers=max_workers,
            root=root,
            all_files=all_files,
            total_files=total_files,
            scan_started_at=deps.time(),
            strict=strict_value,
            yara_enabled=yara_enabled_value,
            progress_every=progress_every,
            throttle_sec=throttle_sec,
            partial_output_path=partial_output_path,
            partial_output_every=partial_output_every,
            slow_file_warn_sec=slow_file_warn_sec,
            per_file_timeout_sec=per_file_timeout_sec,
            work_queue_dir=work_queue_dir,
            worker_output_path=worker_output_path,
            scan_session_snapshot=scan_session_snapshot,
        ),
        SchedulerModeDispatchDependencies(
            worker=worker,
            write_partial=write_partial,
            result_retainer=result_retainer,
            derived_cache_writer=derived_cache_writer,
            results=state_results if type(state_results) is dict else None,
        ),
    )


def finalize_scheduler_runner_state(
    *,
    state: object,
    deps: object,
    scheduler_runtime: object,
    scheduler_requested: object,
    strict_value: object,
    freeze_existing_baselines_value: object,
    profile_policy_snapshot: object,
    write_partial: object,
) -> None:
    """Finalize the scheduler pipeline and record suppressed finalizer failures."""
    finalize_scheduler_pipeline_run(
        SchedulerPipelineRunFinalizationRequest(
            state=state,
            dependencies=deps,
            scheduler_runtime=scheduler_runtime,
            finalization_request_factory=SchedulerPipelineFinalizationRequest,
            finalization_dependencies_factory=SchedulerPipelineFinalizationDependencies,
            scheduler_mode=scheduler_requested,
            strict=strict_value,
            freeze_existing_baselines=freeze_existing_baselines_value,
            profile_policy_snapshot=profile_policy_snapshot,
            write_partial=write_partial,
            recoverable_exceptions=RECOVERABLE_RUNTIME_ERRORS,
        )
    )
