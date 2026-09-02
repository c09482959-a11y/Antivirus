"""Canonical scheduler orchestration runner.

Moved from execution during Phase 5 so the pipeline owns ordering/finalization while execution modules only execute claimed work.
"""
from Virus_Scan.core.logging import get_detector_errors
from Virus_Scan.runtime.api import get_init_value
from Virus_Scan.runtime.api import scheduler_runtime_state
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_text
from Virus_Scan.orchestration.scan_session import validate_scan_session_runtime
from Virus_Scan.routing.intrastage_executor_session import (
    close_intrastage_executor_session,
    start_intrastage_executor_session,
)
from Virus_Scan.scheduler.runtime.scan_session_manifest import read_scan_session_manifest


def _scheduler_init_int(name: object, default: object, *, reason: object) -> object:
    value, rejected_reason = scheduler_int(
        get_init_value(name),
        default=default,
        minimum=1,
        reason=reason,
    )
    if rejected_reason:
        return default
    return value


PROFILE_FLUSH_EVERY = _scheduler_init_int(
    'PROFILE_FLUSH_EVERY',
    25,
    reason='scheduler_profile_flush_every_rejected',
)
BULK_PROFILE_FLUSH_EVERY = _scheduler_init_int(
    'BULK_PROFILE_FLUSH_EVERY',
    1000000000,
    reason='scheduler_bulk_profile_flush_every_rejected',
)
_SCHEDULER_RUNNER_DEFAULT_MODE = scheduler_text(
    'process',
    replacement_text='process',
    unsupported_reason='scheduler_pipeline_mode_rejected',
)[0]

_SCHEDULER_RUNNER_DELEGATED_HELPERS = (
    "build_scheduler_file_execution_dependencies",
    "build_scheduler_file_worker",
)

from Virus_Scan.scheduler.orchestration.scheduler_pipeline_dependencies import (
    default_scheduler_pipeline_dependencies,
)

from Virus_Scan.scheduler.orchestration.scheduler_runner_steps import (
    build_scheduler_file_worker_execution,
    finalize_scheduler_runner_state,
    plan_scheduler_runner_targets,
    prepare_scheduler_runner_controls,
    run_scheduler_mode_dispatch,
)
from Virus_Scan.scheduler.orchestration.result_retention import (
    build_scheduler_result_retainer,
)
from Virus_Scan.storage.scan_cache_result_writer.scan_cache_result_writer import (
    ScanCacheResultWriter,
)


plan_scheduler_targets = plan_scheduler_runner_targets
run_scheduler_mode = run_scheduler_mode_dispatch



def run_scheduler_pipeline(root: object, compiled_rules: object=None, max_workers: object=0, *, strict: object=False, per_file_timeout_sec: object=20, progress_every: object=10, throttle_sec: object=0.0, max_files: object=None, freeze_existing_baselines: object=True, defer_profile_flush: object=True, partial_output_path: object=None, partial_output_every: object=10, slow_file_warn_sec: object=2.0, scheduler: object='process', file_list_path: object=None, work_queue_dir: object=None, worker_output_path: object=None, scan_session_manifest_path: object=None, yara_enabled: object=True, requested_engine: object='auto', dependencies: object=None) -> object:
    """Run the canonical scheduler pipeline through explicit dependencies."""
    deps = dependencies or default_scheduler_pipeline_dependencies()
    scheduler_runtime = scheduler_runtime_state()
    get_detector_errors(clear=True)
    scheduler_input = _SCHEDULER_RUNNER_DEFAULT_MODE if scheduler == 'process' else scheduler
    controls, profile_policy_snapshot = prepare_scheduler_runner_controls(
        deps=deps,
        scheduler_runtime=scheduler_runtime,
        scheduler_input=scheduler_input,
        strict=strict,
        defer_profile_flush=defer_profile_flush,
        freeze_existing_baselines=freeze_existing_baselines,
        yara_enabled=yara_enabled,
        profile_flush_every=PROFILE_FLUSH_EVERY,
        bulk_profile_flush_every=BULK_PROFILE_FLUSH_EVERY,
    )
    requested_engine_text, requested_engine_reason = scheduler_text(
        requested_engine,
        replacement_text='auto',
        unsupported_reason='scheduler_requested_engine_rejected',
    )
    if requested_engine_reason:
        raise ValueError(requested_engine_reason)
    target_plan = plan_scheduler_runner_targets(
        deps=deps,
        root=root,
        file_list_path=file_list_path,
        max_files=max_files,
        scheduler_requested=controls.scheduler_requested,
    )
    all_files = tuple(target_plan.files)
    requested_worker_count = max_workers if type(max_workers) is int and max_workers >= 0 else 0
    if controls.scheduler_requested == "queue-child":
        if scan_session_manifest_path is None:
            raise ValueError("queue_child_scan_session_manifest_required")
        scan_session_snapshot = read_scan_session_manifest(scan_session_manifest_path)
        validate_scan_session_runtime(scan_session_snapshot)
    else:
        if scan_session_manifest_path is not None:
            raise ValueError("parent_scan_session_manifest_rejected")
        scan_session_snapshot = deps.build_scan_session_snapshot(
            compiled_rules=compiled_rules,
            yara_enabled=controls.yara_enabled,
            scan_mode=controls.scheduler_requested,
            requested_engine=requested_engine_text or "auto",
            strict=controls.strict,
            per_file_timeout_sec=float(per_file_timeout_sec),
            slow_file_warn_sec=float(slow_file_warn_sec),
            worker_count=requested_worker_count,
        )
    result_retainer = build_scheduler_result_retainer(
        scheduler_mode=controls.scheduler_requested,
        requested_engine=requested_engine_text or 'auto',
        yara_enabled=controls.yara_enabled,
    )
    derived_cache_writer = ScanCacheResultWriter(
        scan_session_snapshot.cache_execution_identity
    )
    start_intrastage_executor_session(scan_session_snapshot)
    try:
        state, write_partial, worker = build_scheduler_file_worker_execution(
            deps=deps,
            root=root,
            compiled_rules=compiled_rules,
            per_file_timeout_sec=per_file_timeout_sec,
            slow_file_warn_sec=slow_file_warn_sec,
            strict_value=controls.strict,
            yara_enabled_value=controls.yara_enabled,
            partial_output_path=partial_output_path,
            partial_output_every=partial_output_every,
            total_files=target_plan.total_files,
            scan_session_snapshot=scan_session_snapshot,
        )
        try:
            state.results = run_scheduler_mode_dispatch(
                deps=deps,
                state_results=state.results,
                scheduler_requested=controls.scheduler_requested,
                worker=worker,
                result_retainer=result_retainer,
                derived_cache_writer=derived_cache_writer,
                write_partial=write_partial,
                root=root,
                all_files=all_files,
                total_files=target_plan.total_files,
                max_workers=max_workers,
                strict_value=controls.strict,
                yara_enabled_value=controls.yara_enabled,
                progress_every=progress_every,
                throttle_sec=throttle_sec,
                partial_output_path=partial_output_path,
                partial_output_every=partial_output_every,
                slow_file_warn_sec=slow_file_warn_sec,
                per_file_timeout_sec=per_file_timeout_sec,
                work_queue_dir=work_queue_dir,
                worker_output_path=worker_output_path,
                scan_session_snapshot=scan_session_snapshot,
            )
        finally:
            finalize_scheduler_runner_state(
                state=state,
                deps=deps,
                scheduler_runtime=scheduler_runtime,
                scheduler_requested=controls.scheduler_requested,
                strict_value=controls.strict,
                freeze_existing_baselines_value=controls.freeze_existing_baselines,
                profile_policy_snapshot=profile_policy_snapshot,
                write_partial=write_partial,
            )
        return state.results
    finally:
        close_intrastage_executor_session(scan_session_snapshot)
