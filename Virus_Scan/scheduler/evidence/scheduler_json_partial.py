"""Partial scheduler checkpoint publication ownership."""
from __future__ import annotations

from Virus_Scan.contracts.checkpoint import JsonSafeCheckpointDelta
from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.scheduler.evidence.partial_output_support import emit_partial_output_log
from Virus_Scan.scheduler.evidence.scheduler_json_partial_decision import (
    SchedulerCheckpointDecision,
    scheduler_checkpoint_decision,
    unchanged_checkpoint_time,
)


def _commit_checkpoint_payload(
    decision: SchedulerCheckpointDecision,
    *,
    write_partial_scan_results: object,
    make_json_safe: object,
    checkpoint_cache: PartialCheckpointCache | None,
    log_error: object,
) -> bool:
    payload = decision.payload
    if payload is None:
        raise RuntimeError("checkpoint_due_payload_missing")
    if type(payload) is JsonSafeCheckpointDelta and not payload.items:
        return True
    written = write_partial_scan_results(
        decision.target,
        payload,
        make_json_safe=make_json_safe,
    )
    if written is not True:
        emit_partial_output_log(
            log_error,
            "partial JSON save failed: scheduler partial writer returned false",
        )
        return False
    if (
        type(checkpoint_cache) is PartialCheckpointCache
        and type(payload) is JsonSafeCheckpointDelta
    ):
        checkpoint_cache.commit_delta(payload)
    return True


def _publish_checkpoint_decision(
    decision: SchedulerCheckpointDecision,
    *,
    write_partial_scan_results: object,
    make_json_safe: object,
    checkpoint_cache: PartialCheckpointCache | None,
    log_error: object,
) -> float:
    try:
        committed = _commit_checkpoint_payload(
            decision,
            write_partial_scan_results=write_partial_scan_results,
            make_json_safe=make_json_safe,
            checkpoint_cache=checkpoint_cache,
            log_error=log_error,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        emit_partial_output_log(
            log_error,
            "partial JSON save failed: scheduler partial writer raised",
        )
        return decision.last_written
    return decision.current if committed else decision.last_written


def write_partial_scheduler_results(
    *,
    partial_output_path: object,
    results: object,
    total_files: object,
    partial_output_every: object,
    last_partial_write: object,
    now: object,
    environ_get: object,
    write_partial_scan_results: object,
    make_json_safe: object,
    log_error: object,
    checkpoint_cache: PartialCheckpointCache | None = None,
    force: object = False,
) -> float:
    """Observe terminal state and commit only a due append-only delta."""
    decision = scheduler_checkpoint_decision(
        partial_output_path=partial_output_path, results=results,
        total_files=total_files, partial_output_every=partial_output_every,
        last_partial_write=last_partial_write, now=now,
        environ_get=environ_get, make_json_safe=make_json_safe,
        log_error=log_error, checkpoint_cache=checkpoint_cache, force=force,
    )
    if decision is None or not decision.should_write:
        return unchanged_checkpoint_time(
            decision,
            last_partial_write=last_partial_write,
            log_error=log_error,
        )
    return _publish_checkpoint_decision(
        decision,
        write_partial_scan_results=write_partial_scan_results,
        make_json_safe=make_json_safe,
        checkpoint_cache=checkpoint_cache,
        log_error=log_error,
    )


__all__ = ("write_partial_scheduler_results",)
