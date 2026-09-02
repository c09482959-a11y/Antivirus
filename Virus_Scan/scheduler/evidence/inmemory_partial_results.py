"""In-memory scheduler incremental checkpoint publication."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.runtime.queue_json import make_json_safe
from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.scheduler.evidence.inmemory_partial_result_decisions import (
    inmemory_partial_publication_decision,
    inmemory_partial_writer_failed_result,
)


@dataclass(frozen=True, slots=True)
class InMemoryPartialPublicationRequest:
    """Complete canonical input for one process-parent checkpoint commit."""

    partial_output_path: object
    results: object
    partial_output_every: object
    writer: object
    checkpoint_cache: PartialCheckpointCache
    log_error: object
    recoverable_exceptions: object
    terminal_key: object = None
    terminal_record: object = None
    force: object = False


def _observe_terminal_if_enabled(
    request: InMemoryPartialPublicationRequest,
    decision: object,
) -> None:
    if request.terminal_key is None or not decision.target or decision.every <= 0:
        return
    request.checkpoint_cache.observe_terminal(
        request.terminal_key,
        request.terminal_record,
        make_json_safe,
    )


def _publish_pending_delta(request: InMemoryPartialPublicationRequest, target: str) -> bool:
    delta = request.checkpoint_cache.pending_delta()
    if delta.items:
        written = request.writer(target, delta, make_json_safe=make_json_safe)
        if written is not True:
            return False
    request.checkpoint_cache.commit_delta(delta)
    return True


def publish_inmemory_partial_results_from_request(
    request: InMemoryPartialPublicationRequest,
) -> object:
    """Commit only new terminal records after the due decision succeeds."""
    decision = inmemory_partial_publication_decision(
        partial_output_path=request.partial_output_path,
        results=request.results,
        partial_output_every=request.partial_output_every,
        log_error=request.log_error,
        force=request.force,
    )
    try:
        _observe_terminal_if_enabled(request, decision)
    except request.recoverable_exceptions:
        return inmemory_partial_writer_failed_result(
            target=decision.target,
            log_error=request.log_error,
        ).published
    if not decision.should_attempt:
        return decision.should_attempt
    try:
        published = _publish_pending_delta(request, decision.target)
    except request.recoverable_exceptions:
        return inmemory_partial_writer_failed_result(
            target=decision.target,
            log_error=request.log_error,
        ).published
    if published:
        return True
    return inmemory_partial_writer_failed_result(
        target=decision.target,
        log_error=request.log_error,
    ).published


__all__ = (
    "InMemoryPartialPublicationRequest",
    "publish_inmemory_partial_results_from_request",
)
