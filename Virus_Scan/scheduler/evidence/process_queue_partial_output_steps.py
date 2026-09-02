"""Bounded steps for process-queue partial-output publication."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.evidence.process_queue_partial_output_support import (
    process_queue_partial_output_failure,
    process_queue_partial_read_path,
    process_queue_partial_rejection_log_message,
)
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload

if TYPE_CHECKING:
    from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord


def partial_target_missing_result(
    *,
    target_reason: str,
    partial_output_path: object,
    context: str,
) -> tuple[bool, object, tuple[SchedulerEvidenceRecord, ...]]:
    """Return the publication triple for an unavailable target path."""
    evidence: tuple[SchedulerEvidenceRecord, ...] = ()
    if target_reason not in {"", "scheduler_path_missing"}:
        evidence = (
            process_queue_partial_output_failure(
                reason=target_reason,
                field="partial_output_path",
                value=partial_output_path,
                context=context,
            ),
        )
    return False, immutable_mapping(), evidence


def partial_output_read_path(output: object, deps: object, context: str) -> tuple[str | Path | None, tuple[SchedulerEvidenceRecord, ...]]:
    safe_output, evidence, reason = process_queue_partial_read_path(
        output,
        context=context,
    )
    evidence_records: list[SchedulerEvidenceRecord] = []
    if evidence is not None:
        evidence_records.append(evidence)
    if reason:
        try:
            deps.log_error(
                process_queue_partial_rejection_log_message(
                    context,
                    "partial_output_source",
                    reason,
                )
            )
        except deps.recoverable_exceptions as exc:
            evidence_records.append(
                process_queue_partial_output_failure(
                    reason="partial_output_rejection_log_failed",
                    field="partial_output_source_log",
                    value=exc,
                    context=context,
                )
            )
    return safe_output, tuple(evidence_records)


def merge_partial_output_sources(*, outputs: tuple[object, ...], deps: object, context: str) -> tuple[dict[object, object], list[SchedulerEvidenceRecord]]:
    """Read and merge valid partial-output source mappings with evidence."""
    evidence_records: list[SchedulerEvidenceRecord] = []
    partial_merged: dict[object, object] = {}
    for output in outputs:
        safe_output, path_evidence = partial_output_read_path(output, deps, context)
        evidence_records.extend(path_evidence)
        if safe_output is None:
            continue
        if Path(safe_output).exists():
            data = deps.read_json_file(safe_output, default={})
            data_items = no_hook_mapping_items(data)
            if data_items is None:
                evidence_records.append(
                    process_queue_partial_output_failure(
                        reason="partial_output_source_not_mapping",
                        field="partial_output_source_payload",
                        value=data,
                        context=context,
                    )
                )
                continue
            for key, item in data_items:
                partial_merged[key] = item
    return partial_merged, evidence_records


def publish_merged_partial_output(*, target_path: str, merged: dict[object, object], context: str, deps: object) -> tuple[bool, object]:
    if write_worker_output_payload(target_path, merged) is not True:
        raise OSError("process queue monitor partial output publication rejected")
    return True, immutable_mapping(dict(merged))


def publication_failure_evidence(*, deps: object, exc: BaseException, context: str) -> list[SchedulerEvidenceRecord]:
    evidence_records: list[SchedulerEvidenceRecord] = []
    try:
        deps.log_error("process queue monitor partial JSON publication failed")
    except deps.recoverable_exceptions as log_exc:
        evidence_records.append(
            process_queue_partial_output_failure(
                reason="partial_output_publication_log_failed",
                field="partial_output_publication_log",
                value=log_exc,
                context=context,
            )
        )
    evidence_records.append(
        process_queue_partial_output_failure(
            reason="partial_output_publication_failed",
            field="partial_output_publication",
            value=exc,
            context=context,
            fatal=True,
        )
    )
    return evidence_records


__all__ = (
    "merge_partial_output_sources",
    "partial_output_read_path",
    "partial_target_missing_result",
    "publication_failure_evidence",
    "publish_merged_partial_output",
)
