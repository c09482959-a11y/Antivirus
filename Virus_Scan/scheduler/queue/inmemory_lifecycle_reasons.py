"""Static no-hook lifecycle rejection reason selection."""
from __future__ import annotations

_LIFECYCLE_REJECTION_REASONS = (
    ("epoch", "lifecycle_epoch_rejected"),
    ("sequence", "lifecycle_sequence_rejected"),
    ("job_id", "lifecycle_job_id_rejected"),
    ("attempt", "lifecycle_attempt_rejected"),
    ("transition", "lifecycle_transition_rejected"),
    ("monotonic_ns", "lifecycle_monotonic_ns_rejected"),
    ("timestamp", "lifecycle_timestamp_rejected"),
    ("worker_pid", "lifecycle_worker_pid_rejected"),
    ("reason", "lifecycle_reason_rejected"),
    ("state", "lifecycle_state_rejected"),
)


def lifecycle_rejection_reason(field: str) -> str:
    for expected, reason in _LIFECYCLE_REJECTION_REASONS:
        if field == expected:
            return reason
    return "lifecycle_field_rejected"


__all__ = ("lifecycle_rejection_reason",)
