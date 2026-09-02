"""Public scheduler API for final JSON scheduler-evidence projection."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.contracts.retained_scan_result import (
    retained_result_marker_present,
    validate_retained_scan_result,
)
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_exact_fields import exact_mapping_items, is_exact_mapping
from Virus_Scan.scheduler.evidence.final_json_fields import (
    build_final_json_compact_error_fields as _build_final_json_compact_error_fields,
    build_final_json_scheduler_fields as _build_final_json_scheduler_fields,
    scheduler_fields_from_section as _scheduler_fields_from_section,
)
from Virus_Scan.scheduler.evidence.final_json_projection import (
    build_final_json_compact_error_section as _build_final_json_compact_error_section,
    build_final_json_scheduler_section as _build_final_json_scheduler_section,
)
from Virus_Scan.scheduler.evidence.records import build_scheduler_json_evidence_section
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping, unsupported_scheduler_value_evidence

if TYPE_CHECKING:
    from collections.abc import Mapping


def build_scheduler_final_json_section(record: object) -> object:
    """Return the scheduler-owned final JSON evidence section for a result record."""
    return _build_final_json_scheduler_section(record)


def build_scheduler_final_json_compact_error_section(record: object, *, error_type: str, message: str = "") -> object:
    """Return scheduler-owned evidence for recoverable final JSON compaction failures."""
    return _build_final_json_compact_error_section(record, error_type=error_type, message=message)


def build_scheduler_final_json_fields(record: object) -> object:
    """Return scheduler-owned final JSON fields for a compact record."""
    return _build_final_json_scheduler_fields(record)


def attach_scheduler_final_json_fields(record: Mapping[str, object]) -> dict[str, object]:
    """Return a result record carrying canonical scheduler final-JSON fields."""
    if retained_result_marker_present(record):
        validate_retained_scan_result(record)
        retained = materialize_scheduler_mapping(record)
        if type(retained) is not dict:
            return _scheduler_api_failure_fields(record, field_name="scheduler_final_json_record")
        return retained
    if not is_exact_mapping(record):
        return _scheduler_api_failure_fields(record, field_name="scheduler_final_json_record")
    base = materialize_scheduler_mapping(record)
    if type(base) is not dict:
        return _scheduler_api_failure_fields(record, field_name="scheduler_final_json_record")
    dict.update(base, build_scheduler_final_json_fields(record))
    return base


def enrich_scheduler_final_json_results(results: Mapping[str, object]) -> dict[str, object]:
    """Return result mapping enriched with scheduler-owned final JSON fields.

    Orchestration calls this before publication so publication consumes immutable
    result fields instead of importing scheduler implementation or API modules.
    """
    items = exact_mapping_items(results)
    if items is None:
        return {
            "__scheduler_results_unavailable__": _scheduler_api_failure_fields(
                results,
                field_name="scheduler_final_json_results",
            )
        }
    enriched: dict[str, object] = {}
    for index, (path, record) in enumerate(items):
        if type(path) is str:
            output_path = str.__str__(path)
        else:
            output_path = "unsupported_scheduler_result_key_" + int.__str__(index)
        record_items = exact_mapping_items(record)
        if record_items is not None:
            enriched[output_path] = attach_scheduler_final_json_fields(
                scheduler_str_key_mapping_from_items(record_items)
            )
        else:
            enriched[output_path] = _scheduler_api_failure_fields(
                record,
                field_name="scheduler_final_json_result_record",
            )
    return enriched


def _scheduler_api_failure_fields(value: object, *, field_name: str) -> dict[str, object]:
    safe_field_name = str.__str__(field_name) if type(field_name) is str and field_name else "scheduler_api_field"
    section = build_scheduler_json_evidence_section((
        SchedulerEvidenceRecord(
            stage="scheduler_final_json_api",
            state="failure",
            error_category=safe_field_name + "_rejected",
            error_source="scheduler.api.final_json",
            message="scheduler final JSON input was rejected before hookable materialization",
            context={
                safe_field_name: unsupported_scheduler_value_evidence(value, field_name=safe_field_name),
                "value_type": no_hook_type_name(value),
            },
            final_json_must_record=True,
            checkpoint_must_record=True,
            replay_must_record=True,
            fatal=True,
        ),
    ))
    return _scheduler_fields_from_section(section)



def build_scheduler_final_json_compact_error_fields(record: object, *, error_type: str, message: str = "") -> object:
    """Return scheduler-owned final JSON fields for compact-record failures."""
    return _build_final_json_compact_error_fields(record, error_type=error_type, message=message)


__all__ = (
    "attach_scheduler_final_json_fields",
    "build_scheduler_final_json_compact_error_fields",
    "build_scheduler_final_json_compact_error_section",
    "build_scheduler_final_json_fields",
    "build_scheduler_final_json_section",
    "enrich_scheduler_final_json_results",
)
