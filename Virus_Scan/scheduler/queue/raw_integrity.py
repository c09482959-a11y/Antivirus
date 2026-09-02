"""Raw queue integrity degradation state helpers."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.queue.raw_accumulator_value_support import coerce_nonnegative_int
from Virus_Scan.scheduler.queue.raw_integrity_decisions import raw_integrity_degraded_decision, raw_integrity_truthy_decision


def _exact_truthy_integrity_value(value: object) -> bool:
    return raw_integrity_truthy_decision(value).truthy


def raw_integrity_degraded(integrity: Mapping[str, object] | None) -> bool:
    """Return whether a raw-queue integrity snapshot is explicitly degraded."""
    return raw_integrity_degraded_decision(integrity).degraded


def apply_integrity_tags(tags: object, integrity: Mapping[str, object] | None, *, marker: str = "raw_accumulator_incomplete", scanner_degraded_tags: object) -> list[object]:
    """Apply raw-queue degraded tags without changing semantic scoring."""
    tag_values = [no_hook_materialize(item, reason_prefix="raw_integrity_tag") for item in no_hook_sequence_items(tags)]
    if raw_integrity_degraded(integrity):
        marker_text = marker if type(marker) is str and marker != "" else "raw_accumulator_incomplete"
        return scanner_degraded_tags([*tag_values, marker_text])
    return tag_values


def mark_raw_integrity_failure(
    path: object,
    integrity: Mapping[str, object] | None,
    *,
    marker: object,
    exc: BaseException | None = None,
    where: object = "raw_queue",
    set_scan_integrity: object,
    report: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> dict[str, object]:
    """Mark raw-queue integrity failure as incomplete and non-learnable."""
    items = () if integrity is None else no_hook_mapping_items(integrity, allow_dict_subclass=True)
    if items is None:
        info: dict[str, object] = {
            "raw_integrity_unavailable": True,
            "raw_integrity_unavailable_reason": "unsafe_raw_integrity_rejected",
        }
    else:
        info = {key: no_hook_materialize(value, reason_prefix="raw_integrity") for key, value in items if type(key) is str}
    marker_text = marker if type(marker) is str and marker != "" else where if type(where) is str and where != "" else "raw_queue"
    where_text = where if type(where) is str and where != "" else "raw_queue"
    failed_count = dict.get(info, "raw_failed", 0)
    info.update(
        {
            "had_degraded_stage": True,
            "raw_failed": max(1, coerce_nonnegative_int(failed_count, 0)),
            "scan_incomplete": True,
            "allow_learning": False,
            "stage120_marker": marker_text,
        }
    )
    if exc is not None:
        if "failure_info" not in info:
            info["failure_info"] = {
                "stage": where_text,
                "exception_type": no_hook_type_name(exc),
                "error": scheduler_exception_text(exc, missing_text="raw_integrity_exception_unavailable"),
            }
        report(where_text, exc)
    try:
        set_scan_integrity(path, info)
    except recoverable_exceptions as set_exc:
        report("stage120.scan_integrity_update_failed", set_exc)
    return info
