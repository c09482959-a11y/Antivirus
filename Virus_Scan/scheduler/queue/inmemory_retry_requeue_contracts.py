"""Typed boundary contracts for in-memory retry requeue publication."""
from __future__ import annotations

from collections import deque
from collections.abc import Callable

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import LifecycleRequestRecorder
from typing import MutableMapping, MutableSet, TypeAlias

RetryJobRecord = dict[str, object]
RetryJobRecords = MutableMapping[int, RetryJobRecord]
RetryPendingQueue = deque[tuple[int, object, int]]
RetryResults = MutableMapping[object, object]
RetryTerminalSet = MutableSet[int]
RetryEvidenceRecord = dict[str, object]
RetryEvidenceRecords = list[RetryEvidenceRecord]


RetryLifecycleRecorder: TypeAlias = LifecycleRequestRecorder
RetryWorkerErrorResult: TypeAlias = Callable[[object, BaseException | str], RetryJobRecord]


__all__ = (
    "RetryEvidenceRecord",
    "RetryEvidenceRecords",
    "RetryJobRecord",
    "RetryJobRecords",
    "RetryLifecycleRecorder",
    "RetryPendingQueue",
    "RetryResults",
    "RetryTerminalSet",
    "RetryWorkerErrorResult",
)
