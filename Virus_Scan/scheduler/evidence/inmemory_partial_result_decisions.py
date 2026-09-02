"""Typed decisions for in-memory scheduler partial-result publication."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.evidence.partial_output_support import (
    emit_partial_output_log,
    partial_due_by_count,
    partial_every_value,
    partial_force_value,
    partial_output_target,
    partial_result_count,
)


@dataclass(frozen=True)
class InMemoryPartialPublicationDecision:
    """Replayable pre-write decision for in-memory partial-result publication."""

    should_attempt: bool
    target: str
    result_count: int
    every: int
    force: bool
    reason: str


@dataclass(frozen=True)
class InMemoryPartialPublicationResult:
    """Replayable post-write result for in-memory partial-result publication."""

    published: bool
    target: str
    reason: str


def inmemory_partial_publication_decision(
    *,
    partial_output_path: object,
    results: object,
    partial_output_every: object,
    log_error: Callable[[str], object],
    force: object = False,
) -> InMemoryPartialPublicationDecision:
    """Build a no-hook, replayable decision for whether a partial write should be attempted."""

    context = "inmemory_partial_results"
    target, target_reason = partial_output_target(partial_output_path, context=context, log_error=log_error)
    if target == "":
        reason = target_reason or "partial_output_target_unavailable"
        return InMemoryPartialPublicationDecision(should_attempt=False, target="", result_count=0, every=0, force=False, reason=reason)
    result_count = partial_result_count(results, context=context, log_error=log_error)
    if result_count is None:
        return InMemoryPartialPublicationDecision(should_attempt=False, target=target, result_count=0, every=0, force=False, reason="partial_results_count_unavailable")
    every = partial_every_value(partial_output_every, context=context, log_error=log_error)
    if every <= 0:
        return InMemoryPartialPublicationDecision(should_attempt=False, target=target, result_count=result_count, every=every, force=False, reason="partial_output_every_disabled")
    force_value = partial_force_value(force, context=context, log_error=log_error)
    if force_value or partial_due_by_count(result_count, every):
        return InMemoryPartialPublicationDecision(should_attempt=True, target=target, result_count=result_count, every=every, force=force_value, reason="partial_publication_due")
    return InMemoryPartialPublicationDecision(should_attempt=False, target=target, result_count=result_count, every=every, force=force_value, reason="partial_publication_not_due")


def inmemory_partial_writer_failed_result(
    *,
    target: str,
    log_error: Callable[[str], object],
) -> InMemoryPartialPublicationResult:
    emit_partial_output_log(log_error, "in-memory partial JSON save failed: scheduler partial writer raised")
    return InMemoryPartialPublicationResult(published=False, target=target, reason="partial_writer_failed")


__all__ = (
    "InMemoryPartialPublicationDecision",
    "InMemoryPartialPublicationResult",
    "inmemory_partial_publication_decision",
    "inmemory_partial_writer_failed_result",
)
