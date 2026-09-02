"""Replayable decisions for process-queue runner boundary projections."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name


@dataclass(frozen=True, slots=True)
class SchedulerFileRejectionDecision:
    """Replayable decision for rejected scheduler file boundary values."""

    rejected: bool
    reason: str
    rejected_indexes: tuple[int, ...] = ()
    rejected_types: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rejected_indexes", tuple(self.rejected_indexes))
        object.__setattr__(self, "rejected_types", tuple(self.rejected_types))

    def as_bool(self) -> bool:
        """Return the boolean projection used by the runner."""
        return self.rejected


@dataclass(frozen=True, slots=True)
class ProcessQueueEmptyResultDecision:
    """Replayable decision for an empty process-queue input set."""

    accepted: bool
    reason: str
    file_count: int

    def as_mapping(self) -> dict[object, object]:
        """Return the empty mapping projection for callers."""
        return {}


def scheduler_file_rejection_decision(files: tuple[object, ...]) -> SchedulerFileRejectionDecision:
    """Return a replayable no-hook decision for rejected scheduler file sentinels."""
    rejected_indexes: list[int] = []
    rejected_types: list[str] = []
    for index, path in enumerate(files):
        if type(path) is dict and dict.get(path, "unsupported_scheduler_value") is True:
            rejected_indexes.append(index)
            rejected_types.append(no_hook_type_name(path))
    if rejected_indexes:
        return SchedulerFileRejectionDecision(
            rejected=True,
            reason="unsupported_scheduler_file_value_rejected",
            rejected_indexes=tuple(rejected_indexes),
            rejected_types=tuple(rejected_types),
        )
    return SchedulerFileRejectionDecision(
        rejected=bool(),
        reason="scheduler_files_accepted",
    )


def process_queue_empty_result_decision(files: tuple[object, ...]) -> ProcessQueueEmptyResultDecision:
    """Return a replayable decision for empty process-queue work input."""
    return ProcessQueueEmptyResultDecision(
        accepted=True,
        reason="process_queue_empty_input_no_work",
        file_count=len(files),
    )


__all__ = (
    "ProcessQueueEmptyResultDecision",
    "SchedulerFileRejectionDecision",
    "process_queue_empty_result_decision",
    "scheduler_file_rejection_decision",
)
