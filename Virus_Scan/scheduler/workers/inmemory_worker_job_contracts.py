"""Typed contracts for in-memory worker job execution."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Protocol, TypeAlias

WorkerJobPath: TypeAlias = object
WorkerConfigValue: TypeAlias = object
WorkerConfigMapping: TypeAlias = Mapping[str, WorkerConfigValue]
WorkerTaskMetadata: TypeAlias = Mapping[str, WorkerConfigValue]
WorkerQueueMessage: TypeAlias = tuple[object, ...]
WorkerJobOutput: TypeAlias = object
WorkerHeartbeatEvidence: TypeAlias = Mapping[str, object] | None


class WorkerThreadProgressState(Protocol):
    """Callable worker progress state with replayable heartbeat-failure fields."""

    heartbeat_failure_count: object
    last_heartbeat_failure: WorkerHeartbeatEvidence

    def __call__(self, stage: str = "scan", inc: int = 1, bytes_delta: int = 0) -> object: ...


WorkerThreadProgressFactory: TypeAlias = Callable[..., WorkerThreadProgressState]


CancelRequested: TypeAlias = Callable[[object, int, int], bool]
CancelResult: TypeAlias = Callable[[WorkerJobPath, str], WorkerJobOutput]
ResultPublisher: TypeAlias = Callable[[WorkerQueueMessage], object]
WorkerFileScanner: TypeAlias = Callable[[WorkerJobPath, WorkerConfigMapping], WorkerJobOutput]
WorkerErrorResultBuilder: TypeAlias = Callable[[WorkerJobPath, BaseException], WorkerJobOutput]
HeartbeatUpdater: TypeAlias = Callable[..., object]
SuppressionRecorder: TypeAlias = Callable[[str, BaseException], object]


__all__ = (
    "CancelRequested",
    "CancelResult",
    "HeartbeatUpdater",
    "ResultPublisher",
    "SuppressionRecorder",
    "WorkerConfigMapping",
    "WorkerErrorResultBuilder",
    "WorkerFileScanner",
    "WorkerHeartbeatEvidence",
    "WorkerJobOutput",
    "WorkerJobPath",
    "WorkerQueueMessage",
    "WorkerTaskMetadata",
    "WorkerThreadProgressFactory",
    "WorkerThreadProgressState",
)
