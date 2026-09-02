"""Bounded in-memory parent scheduler iteration helpers."""
import logging
import time
from typing import cast

from Virus_Scan.scheduler.workers.inmemory_lifecycle_policy import inmemory_stage_is_pre_execution, inmemory_start_wait_budget
from Virus_Scan.scheduler.orchestration.inmemory_parent_dispatch import dispatch_inmemory_parent_jobs
from Virus_Scan.scheduler.orchestration.inmemory_parent_result import handle_next_inmemory_parent_result
from Virus_Scan.scheduler.orchestration.inmemory_parent_respawn import InMemoryRespawnSweepRequest, run_inmemory_respawn_sweep
from Virus_Scan.scheduler.orchestration.inmemory_parent_maintenance import InMemoryMaintenanceRequest, InMemoryMaintenanceResult, empty_drain_reconciliation_decision, run_inmemory_parent_maintenance
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_contracts import InMemoryParentRuntimeSetupResult, InMemoryRecoveryMaintenanceProtocol


class _RootProgressLogger:
    def info(self, message: str, *args: object) -> None:
        logging.info(message, *args)


_PROGRESS_LOGGER = _RootProgressLogger()



def dispatch_longlived_parent_jobs(setup: InMemoryParentRuntimeSetupResult) -> int:
    recovery = cast("InMemoryRecoveryMaintenanceProtocol", setup.recovery)
    return dispatch_inmemory_parent_jobs(
        pending=setup.pending,
        job_records=setup.job_records,
        terminal=setup.terminal,
        task_queue=setup.task_q,
        active=setup.active,
        state_index=setup.state_index,
        max_inflight=setup.max_inflight,
        max_queued_unstarted=setup.max_queued_unstarted,
        logical_slots=setup.logical_slots,
        workers=setup.workers,
        recovery=recovery,
        ewma_state=setup.ewma_state,
        now=time.time,
    )


def handle_next_inmemory_parent_result_iteration(setup: InMemoryParentRuntimeSetupResult, *, root: object, partial_output_path: object, partial_output_every: int, started_at: float, progress_every: int, throttle_sec: float, result_retainer: object, derived_cache_writer: object, recoverable_exceptions: tuple[type[BaseException], ...]) -> bool:
    recovery = cast("InMemoryRecoveryMaintenanceProtocol", setup.recovery)
    return handle_next_inmemory_parent_result(
        result_queue=setup.result_q,
        job_records=setup.job_records,
        active=setup.active,
        terminal=setup.terminal,
        failed=setup.failed,
        done=setup.done,
        results=setup.results,
        recovery=recovery,
        state_index=setup.state_index,
        root=root,
        routing_evidence_context=setup.routing_evidence_context,
        worker_heartbeats=setup.worker_heartbeats,
        worker_metrics=setup.worker_metrics,
        heartbeat_flags=setup.heartbeat_flags,
        partial_output_path=partial_output_path,
        partial_output_every=partial_output_every,
        started_at=started_at,
        progress_every=progress_every,
        throttle_sec=throttle_sec,
        result_retainer=result_retainer,
        derived_cache_writer=derived_cache_writer,
        recoverable_exceptions=recoverable_exceptions,
    )


def run_inmemory_respawn_sweep_iteration(setup: InMemoryParentRuntimeSetupResult, respawn_sequence: int, *, recoverable_exceptions: tuple[type[BaseException], ...]) -> int:
    respawn_output = run_inmemory_respawn_sweep(
        InMemoryRespawnSweepRequest(
            ctx=setup.ctx,
            procs=setup.procs,
            pending=setup.pending,
            active=setup.active,
            target_workers=setup.workers,
            task_queue=setup.task_q,
            result_queue=setup.result_q,
            worker_config=setup.cfg,
            lifecycle_epoch=setup.lifecycle_epoch,
            respawn_sequence=respawn_sequence,
            state_index=setup.state_index,
            worker_metrics=setup.worker_metrics,
            recoverable_exceptions=recoverable_exceptions,
        )
    )
    return respawn_output.respawn_sequence


def run_inmemory_parent_maintenance_iteration(setup: InMemoryParentRuntimeSetupResult, *, now: float, last_log: float, progress_every: int, total_files: int, last_progress_total: int, recoverable_exceptions: tuple[type[BaseException], ...]) -> InMemoryMaintenanceResult:
    recovery = cast("InMemoryRecoveryMaintenanceProtocol", setup.recovery)
    return run_inmemory_parent_maintenance(
        InMemoryMaintenanceRequest(
            procs=setup.procs,
            active=setup.active,
            terminal=setup.terminal,
            retry_job=recovery.retry_or_fail,
            worker_metrics=setup.worker_metrics,
            memory_policy=setup.memory_policy,
            recovery=recovery,
            job_records=setup.job_records,
            worker_heartbeats=setup.worker_heartbeats,
            heartbeat_table=setup.heartbeat_table,
            heartbeat_flags=setup.heartbeat_flags,
            state_index=setup.state_index,
            max_queued_unstarted=setup.max_queued_unstarted,
            queued_start_timeout_sec=setup.queued_start_timeout_sec,
            assigned_start_timeout_sec=setup.assigned_start_timeout_sec,
            heartbeat_stale_sec=setup.heartbeat_stale_sec,
            progress_stale_sec=setup.progress_stale_sec,
            base_pf_timeout=setup.base_pf_timeout,
            cancel_grace_sec=setup.cancel_grace_sec,
            start_wait_budget=inmemory_start_wait_budget,
            stage_is_pre_execution=inmemory_stage_is_pre_execution,
            ewma_state=setup.ewma_state,
            now=now,
            last_log=last_log,
            progress_every=progress_every,
            total_files=total_files,
            pending=setup.pending,
            last_progress_total=last_progress_total,
            logging_module=_PROGRESS_LOGGER,
            time_time=time.time,
            time_monotonic_ns=time.monotonic_ns,
            recoverable_exceptions=recoverable_exceptions,
        )
    )


def reconcile_or_wait_for_empty_drain(setup: InMemoryParentRuntimeSetupResult, *, submitted: int, total_files: int) -> tuple[bool, bool]:
    recovery = cast("InMemoryRecoveryMaintenanceProtocol", setup.recovery)
    decision = empty_drain_reconciliation_decision(
        pending=setup.pending,
        active=setup.active,
        state_index=setup.state_index,
        recovery=recovery,
        submitted=submitted,
        total_files=total_files,
    )
    recovery.append_empty_drain_evidence(decision.evidence)
    if not decision.should_reconcile:
        return False, False
    retried, failed_now = recovery.requeue_missing_after_empty_drain()
    if retried > 0 or failed_now > 0:
        return True, False
    if recovery.completed >= total_files:
        return False, True
    time.sleep(0.25)
    return False, False
