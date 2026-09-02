"""Worker-owned in-memory worker-exit publication evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class InMemoryWorkerExitPublicationResult:
    """Immutable evidence for publishing a worker-exit message."""

    worker_pid: int
    published: bool
    suppressed_failures: int = 0


def publish_inmemory_worker_exit(
    *,
    result_q: object,
    worker_pid: int,
    timestamp: float,
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
) -> InMemoryWorkerExitPublicationResult:
    """Publish worker-exit evidence without hiding publication failures."""

    try:
        result_q.put(("worker_exit", None, None, int(worker_pid), float(timestamp)))
    except recoverable_exceptions as publish_exc:
        try:
            record_suppressed("inmemory_worker_exit_publication_failure", publish_exc)
        except recoverable_exceptions as record_exc:
            _ = record_exc
        return InMemoryWorkerExitPublicationResult(
            worker_pid=int(worker_pid),
            published=False,
            suppressed_failures=1,
        )
    return InMemoryWorkerExitPublicationResult(worker_pid=int(worker_pid), published=True)


__all__ = ("InMemoryWorkerExitPublicationResult", "publish_inmemory_worker_exit")
