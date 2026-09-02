"""Bounded queue integrity verification orchestration."""
import json
import logging
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.queue.integrity_record_support import (
    identity_text,
    immutable_queue_integrity_summary_dict,
    mark_identity_collection_failure,
    queue_identity_collection_failed_records,
    queue_identity_group_items,
    queue_integrity_initial_summary,
    queue_integrity_summary_dict,
)
from Virus_Scan.scheduler.queue.integrity_repair_actions import process_identity_group


def log_summary_if_needed(summary: dict[str, object], *, phase_text: str) -> None:
    if not (summary["duplicates"] or summary["invalid"] or summary["quarantined"]):
        return
    logging.warning(
        "bulk scan queue integrity %s: duplicates=%s invalid=%s quarantined=%s",
        phase_text,
        summary["duplicates"],
        summary["invalid"],
        summary["quarantined"],
    )


def mark_queue_integrity_exception(
    summary: dict[str, object],
    exc: BaseException,
    *,
    phase: object,
    repair: object,
    report: object,
) -> None:
    summary["integrity_complete"] = False
    summary["integrity_error"] = scheduler_error_detail(exc, max_length=500)
    report(
        "queue_integrity_verify_repair_failed",
        exc,
        fatal=True,
        extra={"phase": phase if type(phase) is str else "", "repair": repair if type(repair) is bool else False},
    )


def maybe_return_identity_collection_failure(
    summary: dict[str, object],
    groups: object,
    *,
    failure_key: str,
) -> dict[str, object] | None:
    failed_records = queue_identity_collection_failed_records(groups, failure_key=failure_key)
    if not failed_records:
        return None
    mark_identity_collection_failure(summary, failed_records)
    return immutable_queue_integrity_summary_dict(summary)


def process_identity_groups(
    summary: dict[str, object],
    groups: object,
    *,
    repair: bool,
    active_claim_is_protected: object,
    quarantine_job: object,
    now: object,
) -> None:
    for ident, items_value in sorted(queue_identity_group_items(groups), key=lambda item: identity_text(item[0])):
        process_identity_group(
            summary,
            ident,
            items_value,
            repair=repair,
            active_claim_is_protected=active_claim_is_protected,
            quarantine_job=quarantine_job,
            now=now,
        )


def verify_queue_integrity_with_dependencies(
    queue_dir: object,
    *,
    all_files: object,
    phase: object,
    repair: bool,
    failure_key: str,
    ensure_dirs: object,
    cleanup_diagnostic_tmp_files: object,
    identity_collector: object,
    active_claim_is_protected: object,
    quarantine_job: object,
    queue_now: object,
    report: object,
) -> dict[str, object]:
    summary = queue_integrity_initial_summary(all_files)
    try:
        ensure_dirs(queue_dir)
        cleanup_diagnostic_tmp_files(queue_dir, max_age_sec=60.0)
        groups = identity_collector(queue_dir)
        failure_summary = maybe_return_identity_collection_failure(summary, groups, failure_key=failure_key)
        if failure_summary is not None:
            return failure_summary
        process_identity_groups(
            summary,
            groups,
            repair=repair,
            active_claim_is_protected=active_claim_is_protected,
            quarantine_job=quarantine_job,
            now=queue_now(),
        )
        log_summary_if_needed(summary, phase_text=phase if type(phase) is str else "")
    except (OSError, TypeError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        mark_queue_integrity_exception(summary, exc, phase=phase, repair=repair, report=report)
    return queue_integrity_summary_dict(summary, repair=repair, phase=phase)
