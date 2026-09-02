"""No-hook queue integrity record materialization helpers."""
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.queue.integrity_contracts import _summary_from_dict
from Virus_Scan.scheduler.queue.integrity_evidence import (
    queue_expected_file_count_decision,
    queue_identity_failure_records_decision,
)

_QUEUE_IDENTITY_GROUPS_MAPPING_REJECTED = "queue identity groups mapping rejected"
_QUEUE_IDENTITY_RECORDS_REJECTED = "queue identity records rejected"
_QUEUE_IDENTITY_RECORD_REJECTED = "queue identity record rejected"


def identity_text(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)
    return no_hook_type_name(value)


def queue_identity_group_items(groups: object) -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(groups)
    if items is None:
        raise TypeError(_QUEUE_IDENTITY_GROUPS_MAPPING_REJECTED)
    return items


def queue_identity_records(records: object) -> tuple[object, ...]:
    if type(records) is list:
        return tuple(records)
    if type(records) is tuple:
        return records
    raise TypeError(_QUEUE_IDENTITY_RECORDS_REJECTED)


def queue_record_mapping(record: object) -> dict[str, object]:
    items = no_hook_mapping_items(record)
    if items is None:
        raise TypeError(_QUEUE_IDENTITY_RECORD_REJECTED)
    return dict(items)


def queue_integrity_initial_summary(all_files: object) -> dict[str, object]:
    expected_file_count = queue_expected_file_count_decision(all_files)
    return {
        "duplicates": 0,
        "quarantined": 0,
        "invalid": 0,
        "expected_files": expected_file_count.count,
        "integrity_complete": True,
        "expected_files_evidence": expected_file_count.evidence,
    }


def queue_identity_collection_failed_records(
    groups: object,
    *,
    failure_key: str,
) -> tuple[dict[str, object], ...]:
    decision = queue_identity_failure_records_decision(groups, failure_key=failure_key)
    return decision.records


def mark_identity_collection_failure(
    summary: dict[str, object],
    failed_records: tuple[dict[str, object], ...],
) -> None:
    summary["integrity_complete"] = False
    summary["integrity_error"] = "queue_identity_collection_failed"
    summary["queue_identity_collection_failed"] = True
    summary["queue_identity_collection_evidence"] = tuple(failed_records)


def queue_integrity_summary_dict(summary: dict[str, object], *, repair: bool, phase: object) -> dict[str, object]:
    immutable_summary = _summary_from_dict(summary)
    if not repair:
        context_text = "queue_integrity:" + (phase if type(phase) is str else "")
        immutable_summary.assert_forensic_complete(context=context_text)
    return immutable_summary.as_dict()


def immutable_queue_integrity_summary_dict(summary: dict[str, object]) -> dict[str, object]:
    return _summary_from_dict(summary).as_dict()
