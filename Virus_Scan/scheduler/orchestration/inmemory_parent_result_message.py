"""Result-message orchestration for parent-side in-memory scheduler messages."""
from __future__ import annotations

from Virus_Scan.core.cache import bulk_scan_maintenance
from Virus_Scan.core.logging import log_bulk_progress
from Virus_Scan.runtime.api import log_error
from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.routing.context_identity import attach_routing_evidence_to_record
from Virus_Scan.scheduler.evidence.inmemory_partial_results import (
    publish_inmemory_partial_results_from_request,
)
from Virus_Scan.scheduler.evidence.inmemory_result_timeout import attach_inmemory_result_evidence
from Virus_Scan.scheduler.orchestration.inmemory_parent_message_contracts import (
    InMemoryParentMessageRequest,
    InMemoryParentMessageResult,
)
from Virus_Scan.scheduler.queue.inmemory_result_completion import complete_inmemory_result_message
from Virus_Scan.scheduler.runtime.stage_budget import record_stage_cost_observation


def handle_inmemory_result_worker_message(request: InMemoryParentMessageRequest) -> InMemoryParentMessageResult:
    complete_inmemory_result_message(
        message=request.message,
        job_records=request.job_records,
        active=request.active,
        terminal=request.terminal,
        failed=request.failed,
        done=request.done,
        results=request.results,
        recovery=request.recovery,
        state_index=request.state_index,
        container_root=request.root,
        routing_evidence_context=request.routing_evidence_context,
        routing_evidence_attacher=attach_routing_evidence_to_record,
        attach_result_evidence=attach_inmemory_result_evidence,
        record_stage_cost_observation=record_stage_cost_observation,
        publish_partial_results=publish_inmemory_partial_results_from_request,
        partial_output_path=request.partial_output_path,
        partial_output_every=request.partial_output_every,
        partial_writer=request.partial_writer,
        partial_checkpoint_cache=request.recovery.partial_checkpoint_cache,
        log_error=log_error,
        bulk_scan_maintenance=bulk_scan_maintenance,
        log_bulk_progress=log_bulk_progress,
        started_at=request.started_at,
        progress_every=request.progress_every,
        throttle_sec=request.throttle_sec,
        result_retainer=request.result_retainer,
        derived_cache_writer=request.derived_cache_writer,
        wall_time=request.wall_time,
        sleep=request.sleep,
        recoverable_exceptions=request.recoverable_exceptions,
        suppressed_recorder=record_scheduler_suppressed,
    )
    return InMemoryParentMessageResult(handled=True, should_continue=False)
