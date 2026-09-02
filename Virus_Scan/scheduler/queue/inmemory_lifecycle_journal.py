"""In-memory scheduler lifecycle journal ownership.

This module owns lifecycle event sequencing for the in-memory scheduler.
It does not execute scans, own timeout policy, mutate queue ownership, or
control runtime bootstrap. The journal is constructor-owned state and exposes
only append behavior to the scheduler loop.
"""



from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_value_snapshot
from Virus_Scan.scheduler.queue.inmemory_lifecycle import make_transition
from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest

_LIFECYCLE_EVENT_SNAPSHOT_FIELDS = (
    "attempt",
    "epoch",
    "job_id",
    "monotonic_ns",
    "reason",
    "sequence",
    "state",
    "timestamp",
    "transition",
    "worker_pid",
)


class InMemoryLifecycleJournal:
    """Constructor-owned lifecycle journal with deterministic sequence numbers."""

    __slots__ = ("_epoch", "_events", "_sequence")

    def __init__(self, *, epoch: int) -> None:
        self._epoch = epoch
        self._sequence = 0
        self._events: list[dict[str, object]] = []

    @property
    def sequence(self) -> int:
        return self._sequence

    def record_request(self, request: InMemoryLifecycleRecordRequest) -> object:
        """Append one canonical immutable lifecycle request."""
        self._sequence += 1
        item = make_transition(
            epoch=self._epoch,
            sequence=self._sequence,
            job_id=request.job_id,
            attempt=request.attempt,
            transition=request.transition,
            worker_pid=request.worker_pid,
            reason=request.reason,
            state=request.state,
        )
        self._events.append(item.to_dict())
        return item

    def snapshot(self) -> tuple[object, ...]:
        """Return an immutable snapshot of recorded lifecycle events."""
        snapshots: list[tuple[tuple[str, object], ...]] = []
        for event in self._events:
            if type(event) is not dict:
                snapshots.append(
                    (
                        ("event_type", no_hook_type_name(event)),
                        ("lifecycle_event_rejected", True),
                        ("reason", "lifecycle_event_mapping_rejected"),
                    )
                )
                continue
            snapshots.append(
                tuple(
                    (field, scheduler_value_snapshot(dict.get(event, field), field_name=field))
                    for field in _LIFECYCLE_EVENT_SNAPSHOT_FIELDS
                )
            )
        return tuple(snapshots)
