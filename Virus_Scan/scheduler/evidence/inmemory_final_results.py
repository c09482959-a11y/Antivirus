"""Final in-memory partial-result publication ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, MutableMapping

from Virus_Scan.scheduler.runtime.queue_json import make_json_safe

from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.scheduler.evidence.inmemory_partial_results import InMemoryPartialPublicationRequest


@dataclass(frozen=True)
class InMemoryFinalPublicationResult:
    attempted: bool
    forced: bool
    published: bool
    failure_reason: str = ""


@dataclass(frozen=True, slots=True)
class InMemoryFinalPublicationRequest:
    """Internal request for one forced final checkpoint publication."""

    partial_output_path: object
    results: MutableMapping[object, object]
    partial_output_every: int
    writer: Callable[..., object]
    checkpoint_cache: PartialCheckpointCache
    log_error: Callable[[str], object]
    publish_partial_results: Callable[[InMemoryPartialPublicationRequest], object]
    recoverable_exceptions: tuple[type[BaseException], ...]


def publish_inmemory_parent_final_results(
    request: InMemoryFinalPublicationRequest,
) -> InMemoryFinalPublicationResult:
    """Force the remaining terminal delta through the canonical journal owner."""
    try:
        request.checkpoint_cache.reconcile_results(request.results, make_json_safe)
        published = request.publish_partial_results(
            InMemoryPartialPublicationRequest(
                partial_output_path=request.partial_output_path,
                results=request.results,
                partial_output_every=request.partial_output_every,
                writer=request.writer,
                checkpoint_cache=request.checkpoint_cache,
                log_error=request.log_error,
                recoverable_exceptions=request.recoverable_exceptions,
                force=True,
            )
        )
    except request.recoverable_exceptions:
        return InMemoryFinalPublicationResult(True, True, False, "partial_publication_raised")
    if type(published) is bool:
        reason = "" if published else "partial_publication_not_written"
        return InMemoryFinalPublicationResult(True, True, published, reason)
    return InMemoryFinalPublicationResult(True, True, False, "partial_publication_result_rejected")


__all__ = (
    "InMemoryFinalPublicationRequest",
    "InMemoryFinalPublicationResult",
    "publish_inmemory_parent_final_results",
)
