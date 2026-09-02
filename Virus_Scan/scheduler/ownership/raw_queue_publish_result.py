"""Typed raw queue publication result contract."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RawQueuePublishRequest:
    published: bool
    reason: str
    pending_name: str = ""
    file_id: str = ""
    seq: int = 0
    attempt: int = 0
    collector: str = ""
    release_failed: bool = False


@dataclass(frozen=True)
class RawQueuePublishResult:
    """Replayable publication outcome for raw-stage queue ownership."""

    published: bool
    reason: str
    pending_name: str = ""
    file_id: str = ""
    seq: int = 0
    attempt: int = 0
    collector: str = ""
    release_failed: bool = False


def raw_queue_publish_result(request: RawQueuePublishRequest) -> RawQueuePublishResult:
    return RawQueuePublishResult(
        request.published,
        request.reason,
        request.pending_name,
        request.file_id,
        request.seq,
        request.attempt,
        request.collector,
        request.release_failed,
    )


def record_raw_queue_publish_failure(deps: object, reason: str) -> None:
    """Record a raw queue publication failure through the injected scheduler reporter."""
    deps.record_suppressed(reason, ValueError(reason))


__all__ = (
    "RawQueuePublishRequest",
    "RawQueuePublishResult",
    "raw_queue_publish_result",
    "record_raw_queue_publish_failure",
)
