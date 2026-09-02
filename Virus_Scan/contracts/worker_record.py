"""Canonical worker output/failure record contracts."""
from __future__ import annotations

from dataclasses import dataclass, field
import math
import time

from Virus_Scan.contracts.no_hook_materialization import no_hook_duplicate_key, no_hook_json_sort_key, no_hook_mapping_items, no_hook_materialize, no_hook_text

_WORKER_EMPTY_TEXT = ""


def _worker_json_sort_key(value: object) -> tuple[int, str]:
    if type(value) is bool or value is None:
        rank = 0
    elif type(value) in (int, float):
        rank = 1
    elif isinstance(value, str):
        rank = 2
    elif type(value) is dict:
        rank = 3
    elif type(value) is list:
        rank = 4
    else:
        rank = 5
    return (rank, no_hook_json_sort_key(value))


def _worker_json_key(index: int) -> str:
    return "worker_output_json_key_" + int.__str__(index)


def _worker_materialize(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        out = {}
        keyed = []
        for index, (key, item) in enumerate(items):
            key_text, key_reason = no_hook_text(
                key,
                missing_reason="missing_worker_output_json_key",
                unsupported_reason="invalid_worker_output_json_key",
            )
            if key_reason or key_text == "":
                key_text = _worker_json_key(index)
            keyed.append((key_text, index, item))
        for raw_key_text, index, item in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in out:
                key_text = no_hook_duplicate_key(key_text, index)
            out[key_text] = _worker_materialize(item)
        return out
    if type(value) in (tuple, list):
        return [_worker_materialize(item) for item in value]
    if type(value) in (set, frozenset):
        return sorted((_worker_materialize(item) for item in value), key=_worker_json_sort_key)
    if type(value) is float and not math.isfinite(value):
        return {"non_finite_float": float.__str__(value)}
    materialized = no_hook_materialize(value, reason_prefix="worker_output_json")
    if type(materialized) is list:
        return materialized
    return materialized


def _safe_worker_text(value: object, *, replacement_text: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_worker_record_text",
        unsupported_reason="unsafe_worker_record_text_value_rejected",
    )
    if reason or text == "":
        replacement, replacement_reason = no_hook_text(
            replacement_text,
            missing_reason="missing_worker_record_default",
            unsupported_reason="unsafe_worker_record_default_rejected",
        )
        return _WORKER_EMPTY_TEXT if replacement_reason else str.strip(replacement)
    return str.strip(text)


@dataclass(frozen=True)
class FailureRecord:
    stage: str
    exception_type: str
    error: str
    domain: str = "scheduler"
    time: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    @classmethod
    def from_error(cls, stage: str, error: BaseException | str, *, domain: str = "scheduler") -> "FailureRecord":
        return cls(
            _safe_worker_text(stage, replacement_text="unknown") or "unknown",
            error.__class__.__name__ if isinstance(error, BaseException) else "Error",
            _safe_worker_text(error, replacement_text="worker_error_unavailable"),
            _safe_worker_text(domain, replacement_text="scheduler") or "scheduler",
        )


def make_json_safe(value: object) -> object:
    return _worker_materialize(value)


__all__ = ("FailureRecord", "make_json_safe")
