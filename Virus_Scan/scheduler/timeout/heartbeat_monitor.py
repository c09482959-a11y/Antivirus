"""Canonical scheduler heartbeat/progress stall interpretation.

Owns deterministic interpretation of heartbeat/progress evidence for queue-worker
state classification.  It does not mutate queue ownership, write evidence, or
perform process termination.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WorkerStallClassification:
    worker_state: str
    timeout_expired: bool
    checkpoint_stalled: bool
    heartbeat_fresh: bool
    pid_alive: bool


def classify_worker_stall_state(
    *,
    timeout_expired: bool,
    checkpoint_stalled: bool,
    heartbeat_fresh: bool,
    pid_alive: bool,
) -> WorkerStallClassification:
    """Classify worker stall state from immutable heartbeat/progress evidence."""
    timeout_expired_b = bool(timeout_expired)
    checkpoint_stalled_b = bool(checkpoint_stalled)
    heartbeat_fresh_b = bool(heartbeat_fresh)
    pid_alive_b = bool(pid_alive)
    if timeout_expired_b:
        state = 'queue_worker_hard_timeout'
    elif checkpoint_stalled_b and heartbeat_fresh_b:
        state = 'queue_worker_progress_stalled'
    elif checkpoint_stalled_b:
        state = 'queue_worker_alive_stalled'
    else:
        state = 'queue_worker_orphaned'
    return WorkerStallClassification(
        worker_state=state,
        timeout_expired=timeout_expired_b,
        checkpoint_stalled=checkpoint_stalled_b,
        heartbeat_fresh=heartbeat_fresh_b,
        pid_alive=pid_alive_b,
    )


__all__ = ('WorkerStallClassification', 'classify_worker_stall_state')
