"""No-hook value support for raw accumulator record transformations."""
from __future__ import annotations

import math
from pathlib import PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from typing import cast

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence

_STDLIB_PATH_TYPES = (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)


def raw_accumulator_failure_record(value: object, *, reason: str) -> dict[str, object]:
    evidence = unsupported_scheduler_value_evidence(value, field_name="raw_accumulator_record")
    return {
        "file_id": "raw_accumulator_unavailable",
        "expected": 0,
        "completed": 0,
        "failed": 0,
        "retried": 0,
        "degraded": True,
        "raw_accumulator_unavailable": True,
        "raw_accumulator_unavailable_reason": reason,
        "raw_failures": [{"collector": "raw_accumulator", "seq": None, "attempt": None, "error": reason, "evidence": evidence}],
        "tags": ["raw_accumulator_unavailable", "scanner_degraded", "scan_incomplete"],
        "yara_hits": [],
        "yara_evidence": None,
        "strings_parts": [],
        "ordered_events": [],
        "errors": [reason],
        "suspicious": False,
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }


def raw_text(value: object, *, field_name: str) -> str:
    field_text = str.__str__(field_name) if type(field_name) is str and field_name else "raw_accumulator_field"
    if type(value) in _STDLIB_PATH_TYPES:
        return PurePath.as_posix(cast("PurePath", value))
    text, reason = no_hook_text(
        value,
        missing_reason="missing_" + field_text,
        unsupported_reason="unsafe_" + field_text + "_rejected",
    )
    if reason or text == "":
        reason_text = reason or "missing_" + field_text
        return "<" + field_text + " " + reason_text + ">"
    return text


def raw_mapping(value: object, *, field_name: str) -> dict[str, object]:
    field_text = str.__str__(field_name) if type(field_name) is str and field_name else "raw_accumulator_field"
    items = no_hook_mapping_items(value)
    if items is None:
        if value is None:
            return {}
        reason = "unsafe_" + field_text + "_rejected"
        return {
            field_text + "_unavailable": True,
            field_text + "_unavailable_reason": reason,
            field_text + "_evidence": unsupported_scheduler_value_evidence(value, field_name=field_text),
        }
    materialized: dict[str, object] = {}
    for index, (key, item) in enumerate(items):
        out_key = key if type(key) is str else "unsupported_" + field_text + "_key_" + str(index)
        materialized[out_key] = no_hook_materialize(item, reason_prefix=field_text)
    return materialized


def raw_sequence(value: object, *, field_name: str) -> list[object]:
    if value is None:
        return []
    items = no_hook_sequence_items(value)
    if not items and type(value) not in {list, tuple, set, frozenset}:
        return [unsupported_scheduler_value_evidence(value, field_name=field_name)]
    return [no_hook_materialize(item, reason_prefix=field_name) for item in items]


def unique_text(values: list[object]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        text, reason = no_hook_text(
            item,
            missing_reason="missing_raw_accumulator_text",
            unsupported_reason="unsafe_raw_accumulator_text_rejected",
        )
        if reason:
            text = "<raw_accumulator_text_unavailable>"
        if text not in seen:
            seen.add(text)
            out.append(text)
    return out


def coerce_nonnegative_int(value: object, default: int = 0) -> int:
    if type(default) is bool:
        safe_default = 1 if default else 0
    elif type(default) is int:
        safe_default = max(default, 0)
    elif type(default) is float and default >= 0.0 and default < math.inf:
        safe_default = int(default)
    else:
        safe_default = 0
    if type(value) is bool:
        return 1 if value else 0
    metric, reason = no_hook_finite_float(value, default=float(safe_default), minimum=0.0)
    if reason:
        return safe_default
    return int(metric)


__all__ = (
    "coerce_nonnegative_int",
    "no_hook_mapping_items",
    "no_hook_materialize",
    "no_hook_text",
    "raw_accumulator_failure_record",
    "raw_mapping",
    "raw_sequence",
    "raw_text",
    "unique_text",
    "unsupported_scheduler_value_evidence",
)
