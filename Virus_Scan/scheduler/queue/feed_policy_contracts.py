"""Immutable contracts for process queue feed policy."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.queue.feed_policy_scalars import (
    FeedPolicyFieldsRequest,
    normalize_feed_decision_fields,
    normalize_feed_policy_fields,
)


@dataclass(frozen=True)
class ProcessQueueFeedPolicy:
    pending_multiplier: float
    min_pending_buffer: int
    pending_buffer: int
    max_file_feed_burst: int
    pressure_pending_buffer: int
    keep_pending_full: bool

    def __post_init__(self) -> None:
        fields = normalize_feed_policy_fields(
            FeedPolicyFieldsRequest(
                pending_multiplier=self.pending_multiplier,
                min_pending_buffer=self.min_pending_buffer,
                pending_buffer=self.pending_buffer,
                max_file_feed_burst=self.max_file_feed_burst,
                pressure_pending_buffer=self.pressure_pending_buffer,
                keep_pending_full=self.keep_pending_full,
            )
        )
        names = (
            "pending_multiplier",
            "min_pending_buffer",
            "pending_buffer",
            "max_file_feed_burst",
            "pressure_pending_buffer",
            "keep_pending_full",
        )
        for name, value in zip(names, fields, strict=True):
            object.__setattr__(self, name, value)


@dataclass(frozen=True)
class ProcessQueueFeedDecision:
    target_workers: int
    pending_buffer: int
    desired_file_live: int
    feed_capacity: int

    def __post_init__(self) -> None:
        fields = normalize_feed_decision_fields(
            target_workers=self.target_workers,
            pending_buffer=self.pending_buffer,
            desired_file_live=self.desired_file_live,
            feed_capacity=self.feed_capacity,
        )
        names = ("target_workers", "pending_buffer", "desired_file_live", "feed_capacity")
        for name, value in zip(names, fields, strict=True):
            object.__setattr__(self, name, value)



__all__ = ("ProcessQueueFeedDecision", "ProcessQueueFeedPolicy")
