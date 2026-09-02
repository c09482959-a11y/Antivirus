"""Scheduler contract projection for final JSON records."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.worker_record import make_json_safe
from Virus_Scan.publication.json_finalization.base_projection import bounded_dict, bounded_list
from Virus_Scan.contracts.no_hook_materialization import exact_bool_or_none
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_get,
    final_json_mapping_items,
    final_json_type_name,
)
from Virus_Scan.publication.json_finalization.base_projection_boundaries import (
    bounded_text_value,
    json_key_result,
    projection_value_sort_key,
)

PLR2004N32 = 32

_MISSING = object()
_CLEAN_SCHEDULER_STATUSES = frozenset(("ok", "clean", "success", "passed", "complete", "completed"))
_NATIVE_TIMEOUT_SCALAR_MISSING = object()


def _exact_timeout_scalar(value: object, *, width: int = 512) -> object:
    if type(value) is str:
        return str.__str__(value)[:width]
    if type(value) in (int, float, bool) or value is None:
        return value
    return _NATIVE_TIMEOUT_SCALAR_MISSING


def _project_timeout_value(value: object, *, width: int = 512) -> object:
    scalar = _exact_timeout_scalar(value, width=width)
    if scalar is not _NATIVE_TIMEOUT_SCALAR_MISSING:
        return scalar
    if type(value) is list:
        return [bounded_text_value(item, 256) for item in value[:16]]
    if final_json_mapping_items(value) is not None:
        return bounded_dict(value, 12)
    return bounded_text_value(value, width)


def _scheduler_projection_failure(reason: str, value: object) -> dict[str, object]:
    return {
        "scheduler_projection_failed": True,
        "status": "failed",
        "failed": True,
        "error_category": reason,
        "error_source": "publication.json_finalization.scheduler_projection",
        "message": "scheduler final JSON projection rejected an unsafe value",
        "reason": reason,
        "value_type": final_json_type_name(value),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }


def _exact_scheduler_status(value: object) -> str | None:
    if type(value) is not str:
        return None
    return str.__str__(value)


def _scheduler_status_is_clean(value: object) -> bool:
    text = _exact_scheduler_status(value)
    return text is not None and text.lower() in _CLEAN_SCHEDULER_STATUSES


def _scheduler_status_is_missing(value: object) -> bool:
    return value is _MISSING


def existing_scheduler_final_json_fields(record: Mapping[str, object]) -> dict[str, object]:
    """Return scheduler fields already carried on the immutable result record.

    Publication owns writing final JSON, not constructing scheduler evidence.
    Scheduler/orchestration must attach the canonical scheduler section before
    this boundary.  This helper only copies already-published scheduler contract
    fields into the compact record and never imports scheduler implementation or
    API modules.
    """
    if final_json_mapping_items(record) is None:
        return {"scheduler": _scheduler_projection_failure("unsupported_scheduler_record", record)}
    fields: dict[str, object] = {}
    scheduler = final_json_mapping_get(record, "scheduler", _MISSING)
    status = final_json_mapping_get(record, "scheduler_status", _MISSING)
    evidence = final_json_mapping_get(record, "scheduler_failure_evidence", _MISSING)
    projection_failures: list[dict[str, object]] = []
    if final_json_mapping_items(scheduler) is not None:
        safe_scheduler = make_json_safe(scheduler)
        if type(safe_scheduler) is dict:
            fields["scheduler"] = safe_scheduler
            if _scheduler_status_is_missing(status):
                status = dict.get(safe_scheduler, "scheduler_status", dict.get(safe_scheduler, "status", _MISSING))
            if evidence is _MISSING:
                evidence = dict.get(
                    safe_scheduler,
                    "scheduler_failure_evidence",
                    dict.get(safe_scheduler, "evidence", _MISSING),
                )
    elif scheduler is not _MISSING:
        scheduler_failure = _scheduler_projection_failure("unsupported_scheduler_section", scheduler)
        fields["scheduler"] = scheduler_failure
        projection_failures.append(scheduler_failure)

    if status is not _MISSING:
        status_text = _exact_scheduler_status(status)
        if status_text is None or status_text == "":
            projection_failures.append(_scheduler_projection_failure("unsupported_scheduler_status", status))
            status = "failed"
        else:
            status = status_text

    evidence_list: list[object] = []
    if evidence is not _MISSING:
        if type(evidence) in {list, tuple, set, frozenset} or final_json_mapping_items(evidence) is not None:
            evidence_list = make_json_safe(bounded_list(evidence, 128))
            if type(evidence_list) is not list:
                evidence_list = []
                projection_failures.append(
                    _scheduler_projection_failure("unsupported_scheduler_evidence", evidence)
                )
        else:
            projection_failures.append(
                _scheduler_projection_failure("unsupported_scheduler_evidence", evidence)
            )
    evidence_list.extend(projection_failures)

    if evidence_list:
        fields["scheduler_failure_evidence"] = evidence_list
        if projection_failures and (
            _scheduler_status_is_missing(status) or _scheduler_status_is_clean(status)
        ):
            status = "failed"
        elif _scheduler_status_is_missing(status) or _scheduler_status_is_clean(status):
            fatal = any(
                final_json_mapping_items(item) is not None
                and exact_bool_or_none(final_json_mapping_get(item, "fatal")) is True
                for item in evidence_list
            )
            status = "fatal" if fatal else "degraded"
        if "scheduler" in fields and type(fields["scheduler"]) is dict:
            fields["scheduler"]["scheduler_failure_evidence"] = evidence_list
            fields["scheduler"].setdefault("evidence", evidence_list)
            fields["scheduler"]["scheduler_status"] = status

    if not _scheduler_status_is_missing(status):
        fields["scheduler_status"] = status
    return fields


def timeout_evidence_projection(value: object) -> dict[str, object] | None:
    """Preserve canonical timeout/stall evidence without lossy truncation.

    Timeout evidence is a forensic contract from the scheduler ownership
    boundary.  Generic bounded dictionary projection can alphabetically truncate
    required fields such as workload_class, timeout_reason, stall_reason, and
    worker_killed.  Keep the required schema keys first, then include a bounded
    deterministic tail for auxiliary fields.
    """
    items = final_json_mapping_items(value)
    if items is None:
        if value is None:
            return None
        return _scheduler_projection_failure("unsupported_timeout_evidence", value)
    value_by_key = dict(items)
    required_keys = (
        "worker_state",
        "heartbeat_age",
        "progress_age",
        "timeout_budget",
        "timeout_reason",
        "stall_reason",
        "workload_class",
        "current_stage",
        "file_size",
        "archive_member_count",
        "recursion_depth",
        "compression_ratio",
        "worker_killed",
        "worker_recovered",
        "scan_method",
        "stall_budget",
        "heartbeat_stale_budget",
        "deep_scan",
        "estimated_uncompressed_size",
        "largest_member_size",
        "nested_archive_count",
        "image_pixels",
    )
    out: dict[str, object] = {}
    for key in required_keys:
        if key in value_by_key:
            v = dict.__getitem__(value_by_key, key)
            out[key] = _project_timeout_value(v, width=512)
    for index, tail_key in enumerate(sorted(value_by_key.keys(), key=projection_value_sort_key)):
        text_key, key_reason = json_key_result(tail_key, index)
        if text_key in out:
            continue
        if len(out) >= PLR2004N32:
            out["_truncated"] = True
            break
        v = dict.__getitem__(value_by_key, tail_key)
        if key_reason:
            out[text_key] = bounded_text_value(tail_key, 256)
            continue
        out[text_key] = _project_timeout_value(v, width=512)
    return out


__all__ = (
    'existing_scheduler_final_json_fields',
    'timeout_evidence_projection',
)
