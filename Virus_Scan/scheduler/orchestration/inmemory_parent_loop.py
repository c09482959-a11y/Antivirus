"""Canonical in-memory long-lived scheduler execution owner."""
from dataclasses import dataclass
import time

from Virus_Scan.cli.exit_codes import exit_code_for_score as _cli_exit_code_for_score
from Virus_Scan.publication.api import write_partial_scan_results
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.evidence.inmemory_final_results import InMemoryFinalPublicationRequest, publish_inmemory_parent_final_results
from Virus_Scan.scheduler.evidence.inmemory_partial_results import publish_inmemory_partial_results_from_request
from Virus_Scan.scheduler.orchestration.inmemory_parent_shutdown import shutdown_inmemory_parent_manager, shutdown_inmemory_parent_runtime
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_contracts import InMemoryParentRuntimeSetupRequest
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_setup import build_inmemory_parent_runtime
from Virus_Scan.scheduler.orchestration.inmemory_parent_setup_recovery import run_direct_process_setup_recovery
from Virus_Scan.scheduler.orchestration.inmemory_parent_loop_driver import LonglivedParentLoopRequest, drive_longlived_parent_loop

INMEMORY_SCHEDULER_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError)
INMEMORY_TELEMETRY_EXCEPTIONS = (OSError, RuntimeError, ValueError, TypeError, AttributeError)

_INMEMORY_PARENT_ITERATION_OWNERS = (
    "dispatch_longlived_parent_jobs",
    "handle_next_inmemory_parent_result_iteration",
    "run_inmemory_respawn_sweep_iteration",
    "run_inmemory_parent_maintenance_iteration",
    "reconcile_or_wait_for_empty_drain",
    "handle_next_inmemory_parent_result",
    "run_inmemory_respawn_sweep",
    "run_inmemory_parent_maintenance",
    "advance_inmemory_parent_loop_guard",
    "last_progress_total = 0",
)

@dataclass(frozen=True)
class InMemoryParentCountDecision:
    count: int
    accepted: bool
    reason: str
    replayable: bool = True

    def as_count(self) -> int:
        return self.count

@dataclass(frozen=True)
class LonglivedParentResultDecision:
    results: dict[str, object]
    accepted: bool
    reason: str
    replayable: bool = True

    def as_results(self) -> dict[str, object]:
        return dict(self.results)

def owned_failed_count_decision(failed: object) -> InMemoryParentCountDecision:
    if type(failed) is set:
        return InMemoryParentCountDecision(set.__len__(failed), accepted=True, reason="owned_failed_set_counted")
    if type(failed) is frozenset:
        return InMemoryParentCountDecision(frozenset.__len__(failed), accepted=True, reason="owned_failed_frozenset_counted")
    if type(failed) is dict:
        return InMemoryParentCountDecision(dict.__len__(failed), accepted=True, reason="owned_failed_dict_counted")
    if type(failed) is list:
        return InMemoryParentCountDecision(list.__len__(failed), accepted=True, reason="owned_failed_list_counted")
    if type(failed) is tuple:
        return InMemoryParentCountDecision(tuple.__len__(failed), accepted=True, reason="owned_failed_tuple_counted")
    return InMemoryParentCountDecision(count=0, accepted=False, reason="owned_failed_collection_rejected")

def _owned_failed_count(failed: object) -> int:
    return owned_failed_count_decision(failed).as_count()

def empty_longlived_parent_result_decision() -> LonglivedParentResultDecision:
    return LonglivedParentResultDecision(results={}, accepted=False, reason="longlived_parent_no_files")

def _build_longlived_parent_runtime(
    root: object,
    all_files: tuple[str, ...],
    process_count: int,
    *,
    strict: bool,
    yara_enabled: bool,
    per_file_timeout_sec: float,
    slow_file_warn_sec: float,
    environ: object,
    scan_session_snapshot: object,
) -> object:
    return build_inmemory_parent_runtime(
        InMemoryParentRuntimeSetupRequest(
            root=root,
            all_files=tuple(all_files),
            process_count=process_count,
            strict=bool(strict),
            yara_enabled=yara_enabled,
            per_file_timeout_sec=per_file_timeout_sec,
            slow_file_warn_sec=slow_file_warn_sec,
            recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
            scan_session_snapshot=scan_session_snapshot,
            environ=environ,
        )
    )

def _run_direct_recovery(recovery_context: dict[str, object], reason: str) -> object:
    return run_direct_process_setup_recovery(
        **recovery_context, recovery_reason=reason,
    )

def _build_process_recovery_context(
    *, root: object, all_files: object, total_files: int, started_at: float,
    strict: bool, yara_enabled: bool, progress_every: int, throttle_sec: float, partial_output_path: object,
    partial_output_every: int, slow_file_warn_sec: float, per_file_timeout_sec: float,
    result_retainer: object,
    derived_cache_writer: object,
) -> dict[str, object]:
    return dict(
        root=root, all_files=all_files, total_files=total_files, started_at=started_at,
        strict=strict, yara_enabled=yara_enabled, progress_every=progress_every, throttle_sec=throttle_sec,
        partial_output_path=partial_output_path, partial_output_every=partial_output_every,
        slow_file_warn_sec=slow_file_warn_sec, per_file_timeout_sec=per_file_timeout_sec,
        recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS, result_retainer=result_retainer,
        derived_cache_writer=derived_cache_writer,
    )

def _run_longlived_process_queue(
    root: object, all_files: tuple[str, ...] | list[str], process_count: int,
    *, strict: bool = False, yara_enabled: bool = True, progress_every: int = 10,
    throttle_sec: float = 0.0, partial_output_path: object = None,
    partial_output_every: int = 10, slow_file_warn_sec: float = 2.0,
    per_file_timeout_sec: float = 20, result_retainer: object,
    derived_cache_writer: object, scan_session_snapshot: object,
    environ: object = None) -> object:
    """Pure in-memory long-lived process scheduler."""
    if not all_files:
        return empty_longlived_parent_result_decision().as_results()
    started_at = time.time()
    total_files = len(all_files)
    recovery_context = _build_process_recovery_context(
        root=root, all_files=all_files, total_files=total_files, started_at=started_at,
        strict=strict, yara_enabled=yara_enabled, progress_every=progress_every, throttle_sec=throttle_sec,
        partial_output_path=partial_output_path, partial_output_every=partial_output_every,
        slow_file_warn_sec=slow_file_warn_sec, per_file_timeout_sec=per_file_timeout_sec,
        result_retainer=result_retainer,
        derived_cache_writer=derived_cache_writer,
    )
    try:
        setup = _build_longlived_parent_runtime(
            root, tuple(all_files), process_count, strict=strict, yara_enabled=yara_enabled,
            per_file_timeout_sec=per_file_timeout_sec, slow_file_warn_sec=slow_file_warn_sec,
            environ=environ, scan_session_snapshot=scan_session_snapshot,
        )
    except PermissionError:
        return _run_direct_recovery(recovery_context, "process_scheduler_setup_permission_denied")
    startup_recovery_work = total_files if type(total_files) is int and type(total_files) is not bool and total_files > 0 else 1
    startup_recovery_timeout = float(per_file_timeout_sec) if type(per_file_timeout_sec) in {int, float} and type(per_file_timeout_sec) is not bool and per_file_timeout_sec > 0 else 20.0
    startup_recovery_deadline = started_at + max(2.0, min(8.0, startup_recovery_timeout * 0.25, float(startup_recovery_work) * 1.5))
    startup_recovery_required = False
    try:
        startup_recovery_required = drive_longlived_parent_loop(LonglivedParentLoopRequest(
                setup=setup,
                root=root,
                total_files=total_files,
                per_file_timeout_sec=per_file_timeout_sec,
                startup_recovery_deadline=startup_recovery_deadline,
                partial_output_path=partial_output_path,
                partial_output_every=partial_output_every,
                progress_every=progress_every,
                throttle_sec=throttle_sec,
                result_retainer=result_retainer,
                derived_cache_writer=derived_cache_writer,
                recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
            ))
    finally:
        shutdown_inmemory_parent_runtime(
            processes=setup.procs,
            task_queue=setup.task_q,
            result_queue=setup.result_q,
            exit_grace_sec=0.5 if startup_recovery_required else None,
        )
        publish_inmemory_parent_final_results(InMemoryFinalPublicationRequest(
            partial_output_path=partial_output_path, results=setup.results,
            partial_output_every=partial_output_every, writer=write_partial_scan_results,
            checkpoint_cache=setup.recovery.partial_checkpoint_cache, log_error=log_error,
            publish_partial_results=publish_inmemory_partial_results_from_request,
            recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
        ))
        shutdown_inmemory_parent_manager(
            manager=setup.manager,
            recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
        )
    if startup_recovery_required:
        return _run_direct_recovery(recovery_context, "process_scheduler_startup_workers_unavailable")
    failed_count = _owned_failed_count(setup.failed)
    if strict and failed_count:
        raise RuntimeError(str.__add__("in-memory scheduler failed jobs: ", int.__str__(failed_count)))
    return {f: setup.results[f] for f in all_files if f in setup.results}

def exit_code_for_score(score: object) -> object:
    return _cli_exit_code_for_score(score)
