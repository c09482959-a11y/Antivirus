"""Process-queue partial-output evidence publication owner.

This module owns monitor-time partial result readback and publication.  The
process-queue execution loop supplies immutable output paths and serialization
callbacks but does not assemble or write partial scheduler evidence directly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, TYPE_CHECKING

from Virus_Scan.scheduler.evidence.partial_output_support import partial_output_target
from Virus_Scan.scheduler.evidence.process_queue_partial_output_steps import (
    merge_partial_output_sources,
    partial_target_missing_result,
    publication_failure_evidence,
    publish_merged_partial_output,
)
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple

if TYPE_CHECKING:
    from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord


@dataclass(frozen=True)
class ProcessQueuePartialOutputRequest:
    outputs: tuple[object, ...]
    partial_output_path: object | None
    context: str = "partial_monitor"

    def __post_init__(self) -> None:
        object.__setattr__(self, "outputs", immutable_tuple(self.outputs))


@dataclass(frozen=True)
class ProcessQueuePartialOutputDependencies:
    read_json_file: Callable[..., object]
    log_error: Callable[[str], None]
    recoverable_exceptions: tuple[type[BaseException], ...]


@dataclass(frozen=True)
class ProcessQueuePartialOutputPublication:
    published: bool
    merged: Mapping[object, object]
    evidence: tuple[SchedulerEvidenceRecord, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "merged", immutable_mapping(self.merged))
        object.__setattr__(self, "evidence", immutable_tuple(self.evidence))


def publish_process_queue_partial_output(
    request: ProcessQueuePartialOutputRequest,
    deps: ProcessQueuePartialOutputDependencies,
) -> ProcessQueuePartialOutputPublication:
    """Publish monitor partial output from immutable output path snapshots."""
    target_path, target_reason = partial_output_target(
        request.partial_output_path,
        context=request.context,
        log_error=deps.log_error,
    )
    if target_path == "":
        published, merged, evidence = partial_target_missing_result(
            target_reason=target_reason,
            partial_output_path=request.partial_output_path,
            context=request.context,
        )
        return ProcessQueuePartialOutputPublication(published=published, merged=merged, evidence=evidence)

    evidence_records: list[SchedulerEvidenceRecord] = []
    try:
        partial_merged, source_evidence = merge_partial_output_sources(
            outputs=request.outputs,
            deps=deps,
            context=request.context,
        )
        evidence_records.extend(source_evidence)
        if not partial_merged:
            return ProcessQueuePartialOutputPublication(
                published=False,
                merged=immutable_mapping(),
                evidence=tuple(evidence_records),
            )
        published, merged = publish_merged_partial_output(
            target_path=target_path,
            merged=partial_merged,
            context=request.context,
            deps=deps,
        )
        return ProcessQueuePartialOutputPublication(
            published=published,
            merged=merged,
            evidence=tuple(evidence_records),
        )
    except deps.recoverable_exceptions as exc:
        evidence_records.extend(publication_failure_evidence(deps=deps, exc=exc, context=request.context))
        return ProcessQueuePartialOutputPublication(
            published=False,
            merged=immutable_mapping(),
            evidence=tuple(evidence_records),
        )


__all__ = ("ProcessQueuePartialOutputDependencies", "ProcessQueuePartialOutputPublication", "ProcessQueuePartialOutputRequest", "publish_process_queue_partial_output")
