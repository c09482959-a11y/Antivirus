"""Immutable lifecycle append requests and canonical recorder contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from Virus_Scan.scheduler.queue.inmemory_lifecycle_contracts import InMemoryLifecycleTransition


@dataclass(frozen=True, slots=True)
class InMemoryLifecycleRecordRequest:
    """One immutable lifecycle-journal append request."""

    job_id: object
    attempt: object
    transition: str
    worker_pid: object = 0
    reason: object = ""
    state: object = ""




class LifecycleJournalRecorder(Protocol):
    def record_request(
        self,
        request: InMemoryLifecycleRecordRequest,
    ) -> InMemoryLifecycleTransition | object: ...


class LifecycleRequestRecorder(Protocol):
    def __call__(
        self,
        request: InMemoryLifecycleRecordRequest,
    ) -> InMemoryLifecycleTransition | object: ...


class LifecycleRecorderMixin:
    """Canonical lifecycle request owner."""

    lifecycle_journal: LifecycleJournalRecorder

    def record_lifecycle_request(
        self,
        request: InMemoryLifecycleRecordRequest,
    ) -> InMemoryLifecycleTransition | object:
        return self.lifecycle_journal.record_request(request)


__all__ = (
    "InMemoryLifecycleRecordRequest",
    "LifecycleJournalRecorder",
    "LifecycleRecorderMixin",
    "LifecycleRequestRecorder",
)
