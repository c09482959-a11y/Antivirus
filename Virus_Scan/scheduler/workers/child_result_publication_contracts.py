"""Typed publication contracts for worker child-result persistence."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TypeAlias

SchedulerPublicationValue: TypeAlias = object
WorkerResultRecord: TypeAlias = Mapping[str, object]
ChildResultRecords: TypeAlias = Mapping[str, object]
WorkerPublicationReporter: TypeAlias = Callable[[str, BaseException], object]
RecoverableExceptions: TypeAlias = tuple[type[BaseException], ...]
ChildResultWriter: TypeAlias = Callable[
    [SchedulerPublicationValue, SchedulerPublicationValue, SchedulerPublicationValue, WorkerResultRecord],
    object,
]
@dataclass(frozen=True, slots=True)
class ChildResultPersistRequest:
    queue_dir: SchedulerPublicationValue
    claim_path: SchedulerPublicationValue
    file_path: SchedulerPublicationValue
    result: WorkerResultRecord
    context: str
    write_result: ChildResultWriter
    report: WorkerPublicationReporter
    recoverable_exceptions: RecoverableExceptions = (Exception,)


@dataclass(frozen=True, slots=True)
class WorkerOutputUpdateRequest:
    worker_output_path: SchedulerPublicationValue
    file_path: SchedulerPublicationValue
    result: WorkerResultRecord
    child_results: ChildResultRecords
    report: WorkerPublicationReporter
    context: str = "worker_output"


@dataclass(frozen=True, slots=True)
class WorkerOutputFinalizeRequest:
    worker_output_path: SchedulerPublicationValue
    child_results: ChildResultRecords
    report: WorkerPublicationReporter
    context: str = "worker_output_final"


__all__ = (
    "ChildResultRecords",
    "ChildResultPersistRequest",
    "ChildResultWriter",
    "RecoverableExceptions",
    "SchedulerPublicationValue",
    "WorkerOutputFinalizeRequest",
    "WorkerOutputUpdateRequest",
    "WorkerPublicationReporter",
    "WorkerResultRecord",
)
