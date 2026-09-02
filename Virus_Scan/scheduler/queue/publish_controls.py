"""No-hook process-queue publication control normalization."""
from __future__ import annotations

import logging
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_int
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockAcquireDecision
from Virus_Scan.scheduler.queue.publish_job_contract import ProcessQueuePublishResult


def publish_identity_failure_extra(job: object) -> dict[str, object]:
    items = no_hook_mapping_items(job)
    snapshot = dict(items) if items is not None else {}
    return {
        "file": dict.get(snapshot, "file"),
        "job_type": no_hook_type_name(job),
    }


def process_queue_identity_lock_result(
    value: object,
    identity: str,
    *,
    record_suppressed: Callable[..., object],
) -> tuple[object | None, bool, bool]:
    """Interpret exactly one typed identity-lock acquisition decision."""
    if type(value) is not IdentityLockAcquireDecision:
        record_suppressed(
            "process_queue_identity_lock_decision_invalid",
            TypeError("identity lock owner returned an invalid decision"),
            extra={"identity": identity},
            fatal=True,
        )
        return None, False, True
    if not value.acquired:
        already_locked = value.reason == "process_queue_identity_lock_already_locked"
        return None, already_locked, not already_locked
    if value.lock_path is None:
        record_suppressed(
            "process_queue_identity_lock_decision_invalid",
            ValueError("acquired identity lock decision has no path"),
            extra={"identity": identity},
            fatal=True,
        )
        return None, False, True
    return value.lock_path, False, False


def process_queue_publish_result_tuple(outcome: object) -> tuple[bool, bool, bool]:
    """Project the typed publication result into loop-control flags."""
    if type(outcome) is not ProcessQueuePublishResult:
        return False, False, True
    failed = outcome.guard_exception or outcome.durable_write_failed or outcome.release_failed
    if outcome.published:
        return True, False, failed
    return False, outcome.guard_blocked and not failed, failed


def normalize_queue_slice_controls(
    cursor: object,
    max_new: object,
    ordered_items: object,
    *,
    record_suppressed: Callable[..., object],
) -> tuple[int, int, tuple[object, ...]]:
    max_new_value, max_new_reason = scheduler_int(
        max_new,
        default=0,
        minimum=0,
        reason="process_queue_slice_max_new_invalid",
    )
    if max_new_reason:
        record_suppressed(
            "process_queue_slice_max_new_invalid",
            ValueError(max_new_reason),
            extra={"max_new_type": no_hook_type_name(max_new)},
        )
    cursor_value, cursor_reason = scheduler_int(
        cursor,
        default=0,
        minimum=0,
        reason="process_queue_slice_cursor_invalid",
    )
    if cursor_reason:
        record_suppressed(
            "process_queue_slice_cursor_invalid",
            ValueError(cursor_reason),
            extra={"cursor_type": no_hook_type_name(cursor)},
        )
    if type(ordered_items) not in {tuple, list}:
        failure = ValueError("process_queue_slice_ordered_items_rejected")
        record_suppressed(
            "process_queue_slice_ordered_items_rejected",
            failure,
            extra={"ordered_items_type": no_hook_type_name(ordered_items)},
        )
        raise failure
    return cursor_value, max_new_value, no_hook_sequence_items(ordered_items)


def queue_slice_item(item: object) -> tuple[object, ...] | None:
    if type(item) not in {tuple, list}:
        return None
    return tuple(item)


def normalize_publish_attempt_result(
    value: object,
    *,
    record_suppressed: Callable[..., object],
) -> tuple[bool, bool, bool]:
    if type(value) is not tuple or len(value) != 3:
        record_suppressed(
            "process_queue_publish_attempt_result_rejected",
            ValueError("process_queue_publish_attempt_result_rejected"),
            extra={"result_type": no_hook_type_name(value)},
        )
        return False, False, True
    normalized: list[bool] = []
    for index, item in enumerate(value):
        flag, reason = scheduler_bool(
            item,
            default=False,
            reason="process_queue_publish_attempt_flag_" + str(index) + "_rejected",
        )
        if reason:
            record_suppressed(
                "process_queue_publish_attempt_result_rejected",
                ValueError(reason),
                extra={"flag_index": index, "flag_type": no_hook_type_name(item)},
            )
            return False, False, True
        normalized.append(flag)
    return normalized[0], normalized[1], normalized[2]


def record_publish_summary(
    skipped_duplicates: int,
    failed_publishes: int,
    *,
    record_suppressed: Callable[..., object],
) -> None:
    if skipped_duplicates:
        logging.warning(
            "bulk scan queue enqueue guard: skipped_duplicate_file_jobs=%s",
            skipped_duplicates,
        )
    if failed_publishes:
        record_suppressed(
            "queue_enqueue_publish_failed",
            RuntimeError("failed_queue_job_publishes=" + str(failed_publishes)),
        )


__all__ = (
    "normalize_publish_attempt_result",
    "normalize_queue_slice_controls",
    "process_queue_identity_lock_result",
    "process_queue_publish_result_tuple",
    "publish_identity_failure_extra",
    "queue_slice_item",
    "record_publish_summary",
)
