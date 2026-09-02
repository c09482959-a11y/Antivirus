"""Raw collector context-failure telemetry and degraded tag projection."""
from __future__ import annotations

import math
from typing import Callable

from Virus_Scan.scheduler.internal.immutable_outputs import unsupported_scheduler_value_evidence


_RAW_COLLECTOR_DEFAULT_NAME = "raw_collector"
_RAW_CONTEXT_TAG_FIELD_PREFIX = "raw_context_tag_"


def _degraded_tag_input(tags: object) -> tuple[list[object], dict[str, object] | None]:
    if tags is None:
        return ["raw_context_scan_failed"], None
    tag_items: list[object] | tuple[object, ...]
    if type(tags) is list:
        tag_items = tags
    elif type(tags) is tuple:
        tag_items = tags
    else:
        return ["raw_context_scan_failed"], unsupported_scheduler_value_evidence(tags, field_name="raw_context_tags")
    out: list[object] = []
    unsupported: list[dict[str, object]] = []
    for index, item in enumerate(tag_items):
        if type(item) is str:
            out.append(str.__str__(item))
        else:
            unsupported.append(
                unsupported_scheduler_value_evidence(
                    item,
                    field_name=_RAW_CONTEXT_TAG_FIELD_PREFIX + int.__str__(index),
                )
            )
    out.append("raw_context_scan_failed")
    if unsupported:
        return out, {
            "unsupported_scheduler_value": True,
            "status": "failed",
            "failed": True,
            "stage": "scheduler_raw_collector_context",
            "state": "failed",
            "error_category": "raw_context_tags_unsupported",
            "error_source": "scheduler.evidence.raw_collector_context",
            "message": "raw collector context tags contained unsupported values",
            "field_name": "raw_context_tags",
            "unsupported_values": tuple(unsupported),
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }
    return out, None


def raw_collector_context_failure(
    tags: object,
    collector: object,
    exc: BaseException,
    *,
    path: object = None,
    start: object = 0,
    report: Callable[..., object],
    scanner_degraded_tags: Callable[[list[object]], list[object]],
) -> list[object]:
    """Return degraded tags and record precise collector failure provenance without caller hooks."""
    if type(collector) is str and collector:
        collector_text, collector_evidence = str.__str__(collector), None
    elif collector is None:
        collector_text, collector_evidence = _RAW_COLLECTOR_DEFAULT_NAME, None
    else:
        collector_text = _RAW_COLLECTOR_DEFAULT_NAME
        collector_evidence = unsupported_scheduler_value_evidence(collector, field_name="raw_context_text")
    if type(path) is str:
        path_text, path_evidence = str.__str__(path), None
    elif path is None:
        path_text, path_evidence = "", None
    else:
        path_text = ""
        path_evidence = unsupported_scheduler_value_evidence(path, field_name="raw_context_path")
    if type(start) is int:
        start_value, start_evidence = start, None
    elif type(start) is float and math.isfinite(start):
        start_value, start_evidence = int(start), None
    elif start is None:
        start_value, start_evidence = 0, None
    else:
        start_value = 0
        start_evidence = unsupported_scheduler_value_evidence(start, field_name="raw_context_start")
    degraded_input, tags_evidence = _degraded_tag_input(tags)
    extra: dict[str, object] = {
        "path": path_text,
        "start": start_value,
        "collector": collector_text,
    }
    if collector_evidence is not None:
        extra["collector_evidence"] = collector_evidence
    if path_evidence is not None:
        extra["path_evidence"] = path_evidence
    if start_evidence is not None:
        extra["start_evidence"] = start_evidence
    if tags_evidence is not None:
        extra["tags_evidence"] = tags_evidence
    report(
        "raw_" + collector_text + "_context_scan_failed",
        exc,
        fatal=False,
        extra=extra,
    )
    degraded_result = scanner_degraded_tags(degraded_input)
    if type(degraded_result) is list:
        return degraded_result
    if type(degraded_result) is tuple:
        return list(degraded_result)
    return [
        *degraded_input,
        unsupported_scheduler_value_evidence(degraded_result, field_name="scanner_degraded_tags_result"),
    ]
