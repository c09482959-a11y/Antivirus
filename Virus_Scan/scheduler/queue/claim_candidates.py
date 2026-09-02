"""Queue-owned pending claim candidate selection."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping, unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import (
    QueueListdirFailure,
    queue_listdir_names,
)


def pending_claim_names(
    pending_dir: object,
    *,
    listdir: Callable[[object], object],
    is_job_name: Callable[[str], bool],
    limit: int,
    record_failure: Callable[..., bool] | None = None,
) -> list[str]:
    """Return deterministic pending queue claim names for claim authority."""
    try:
        listed = queue_listdir_names(
            listdir(pending_dir),
            context=pending_dir,
        )
    except QueueListdirFailure as failure:
        where = (
            "queue_pending_claim_listdir_unsupported"
            if failure.reason == "queue_listdir_result_unsupported"
            else "queue_pending_claim_listdir_failed"
        )
        evidence = failure.as_dict()
        if where == "queue_pending_claim_listdir_unsupported":
            evidence["field_name"] = "pending_claim_listdir_result"
        _record_pending_claim_failure(record_failure, where, evidence)
        raise
    names: list[str] = []
    for index, name in enumerate(listed):
        if type(name) is not str:
            _record_pending_claim_failure(
                record_failure,
                "queue_pending_claim_name_rejected",
                unsupported_scheduler_value_evidence(
                    name,
                    field_name="pending_claim_name_" + int.__str__(index),
                ),
            )
            continue
        if is_job_name(name):
            names.append(str.__str__(name))
    if not names:
        return []
    names.sort()
    candidate_count = len(names)
    if type(limit) is int and type(limit) is not bool:
        count_limit = limit
        if count_limit <= 0:
            _record_pending_claim_failure(
                record_failure,
                "queue_pending_claim_limit_rejected",
                {
                    "pending_claim_limit_rejected": True,
                    "field_name": "pending_claim_limit",
                    "reason": "pending_claim_limit_non_positive",
                    "limit_value": limit,
                    "candidate_count_limit": candidate_count,
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_record": True,
                },
            )
            count_limit = candidate_count
    else:
        _record_pending_claim_failure(
            record_failure,
            "queue_pending_claim_limit_rejected",
            unsupported_scheduler_value_evidence(limit, field_name="pending_claim_limit"),
        )
        count_limit = candidate_count
    return names[:count_limit]




def _record_pending_claim_failure(record_failure: Callable[..., bool] | None, reason: str, evidence: object) -> None:
    if record_failure is None:
        return
    reason_text = reason if type(reason) is str else "queue_pending_claim_failure"
    materialized = materialize_scheduler_mapping(evidence)
    if type(materialized) is not dict:
        materialized = unsupported_scheduler_value_evidence(evidence, field_name="pending_claim_failure_evidence")
    try:
        record_failure(
            reason_text,
            RuntimeError(reason_text),
            extra={"pending_claim_names_failure": materialized},
            fatal=True,
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise RuntimeError(reason_text + "_record_failed") from exc


__all__ = ("pending_claim_names",)
