"""In-memory result completion and terminal accounting ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, MutableMapping, MutableSet

from Virus_Scan.scheduler.queue.inmemory_result_completion_contracts import (
    InMemoryCompletedResultDriverRequest,
    InMemoryCompletedResultPublicationRequest,
)
from Virus_Scan.scheduler.queue.inmemory_result_completion_driver import (
    publish_completed_result_and_apply_throttle,
)
from Virus_Scan.scheduler.queue.inmemory_result_completion_steps import (
    apply_completion_terminal_state,
    observe_completion_cost_safely,
    resolve_completion_context,
)


@dataclass(frozen=True)
class InMemoryResultCompletionOutcome:
    handled: bool
    completed_delta: int
    throttled: bool


def complete_inmemory_result_message(
    *,
    message: object,
    job_records: MutableMapping[int, MutableMapping[str, object]],
    active: MutableMapping[int, object],
    terminal: MutableSet[int],
    failed: MutableSet[int],
    done: MutableSet[int],
    results: MutableMapping[object, object],
    recovery: object,
    state_index: object,
    container_root: object,
    routing_evidence_context: object,
    routing_evidence_attacher: Callable[..., object],
    attach_result_evidence: Callable[..., object],
    record_stage_cost_observation: Callable[..., object],
    publish_partial_results: Callable[..., object],
    partial_output_path: object,
    partial_output_every: int,
    partial_writer: Callable[..., object],
    partial_checkpoint_cache: object,
    log_error: Callable[[str], object],
    bulk_scan_maintenance: Callable[[int], object],
    log_bulk_progress: Callable[..., object],
    started_at: float,
    progress_every: int,
    throttle_sec: float,
    result_retainer: Callable[[object, object], object],
    derived_cache_writer: Callable[[object], object],
    wall_time: Callable[[], float],
    sleep: Callable[[float], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
    suppressed_recorder: Callable[[str, BaseException], object],
) -> InMemoryResultCompletionOutcome:
    """Complete a worker result message without owning live orchestration."""
    context = resolve_completion_context(
        message=message,
        job_records=job_records,
        terminal=terminal,
        log_error=log_error,
    )
    if context is None:
        return InMemoryResultCompletionOutcome(handled=False, completed_delta=0, throttled=False)
    apply_completion_terminal_state(
        context=context,
        active=active,
        terminal=terminal,
        failed=failed,
        done=done,
        recovery=recovery,
        state_index=state_index,
        wall_time=wall_time,
    )
    observe_completion_cost_safely(
        context=context,
        record_stage_cost_observation=record_stage_cost_observation,
        wall_time=wall_time,
        recoverable_exceptions=recoverable_exceptions,
        suppressed_recorder=suppressed_recorder,
    )
    publication = InMemoryCompletedResultPublicationRequest(
        parts=context.parts, record=context.record, results=results, recovery=recovery,
        container_root=container_root, routing_evidence_context=routing_evidence_context,
        routing_evidence_attacher=routing_evidence_attacher,
        attach_result_evidence=attach_result_evidence, publish_partial_results=publish_partial_results,
        partial_output_path=partial_output_path, partial_output_every=partial_output_every,
        partial_writer=partial_writer, partial_checkpoint_cache=partial_checkpoint_cache,
        log_error=log_error, bulk_scan_maintenance=bulk_scan_maintenance,
        log_bulk_progress=log_bulk_progress, started_at=started_at, progress_every=progress_every,
        wall_time=wall_time, job_records=job_records, recoverable_exceptions=recoverable_exceptions,
        suppressed_recorder=suppressed_recorder, result_retainer=result_retainer,
        derived_cache_writer=derived_cache_writer,
    )
    throttled = publish_completed_result_and_apply_throttle(
        InMemoryCompletedResultDriverRequest(
            publication=publication, throttle_sec=throttle_sec, sleep=sleep
        )
    )
    return InMemoryResultCompletionOutcome(handled=True, completed_delta=1, throttled=throttled)
