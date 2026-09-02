"""Exact final-JSON field extraction without caller-owned hooks."""
from __future__ import annotations

import math
from collections.abc import Iterable
from types import MappingProxyType
from typing import Mapping, TypeAlias, cast

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.records import collect_scheduler_evidence
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision

ExactMapping: TypeAlias = Mapping[str, object]
ExactMappingItems: TypeAlias = Iterable[tuple[object, object]]
ExactValue: TypeAlias = object
def exact_mapping_items(source: object | None) -> ExactMappingItems | None:
    if type(source) is dict:
        return dict.items(source)
    frozen_decision = frozen_scheduler_items_decision(source)
    if frozen_decision.accepted:
        return frozen_decision.items
    if type(source) is MappingProxyType:
        return no_hook_mapping_items(source)
    return None


def is_exact_mapping(source: object | None) -> bool:
    return exact_mapping_items(source) is not None


def exact_mapping_value(
    source: object | None, key: str, default: object | None = None
) -> object | None:
    items = exact_mapping_items(source)
    if items is None:
        return default
    for item_key, value in items:
        if type(item_key) is str and item_key == key:
            return value
    return default


def first_exact_text(source: object | None, *keys: str, default_text: str = "") -> str:
    for key in keys:
        text = exact_text(exact_mapping_value(source, key))
        if text:
            return text
    return default_text


def exact_text(value: object | None) -> str | None:
    if value is None:
        return ""
    if type(value) is str:
        return str.__str__(value)
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float and math.isfinite(value):
        return float.__str__(value)
    return None


def exact_flag_value(value: object | None, *, default: bool = False) -> bool:
    if type(value) is bool:
        return value
    if type(value) is int:
        return value != 0
    if type(value) is str:
        text = str.__str__(value).lower()
        if text in {"1", "true", "yes", "degraded", "failed", "failure", "fatal", "error", "timeout"}:
            return True
        if text in {"0", "false", "no", "ok", "clean", "passed", "success", "written"}:
            return False
    return default


def exact_flag(source: object | None, *keys: str, default: bool = False) -> bool:
    for key in keys:
        value = exact_mapping_value(source, key)
        if value is not None:
            return exact_flag_value(value, default=default)
    return default


def exact_int_with_rejection(
    source: object | None, key: str, default: int = 0
) -> tuple[int, bool]:
    value = exact_mapping_value(source, key)
    converted, rejected = default, False
    if type(value) is bool:
        converted = int(value)
    elif type(value) is int:
        converted = value
    elif type(value) is float and math.isfinite(value):
        converted = int(value)
    elif value is not None:
        text = exact_text(value)
        if text is None:
            rejected = True
        elif text != "":
            try:
                converted = int(text)
            except ValueError:
                rejected = True
    return converted, rejected


def exact_int(source: object | None, key: str, default: int = 0) -> int:
    value, _rejected = exact_int_with_rejection(source, key, default=default)
    return value


def exact_has_content(value: object | None) -> bool:
    items = exact_mapping_items(value)
    if items is not None:
        return any(True for _item in items)
    if type(value) is list or type(value) is tuple or type(value) is set or type(value) is frozenset:
        return len(value) > 0
    return exact_flag_value(value)


def exact_contains_fragment(value: object | None, fragment: str) -> bool:
    """Search exact scheduler containers without formatting nested values."""
    if type(fragment) is not str or fragment == "":
        return False
    needle = str.__str__(fragment).lower()
    text = exact_text(value)
    if text is not None:
        return needle in text.lower()
    items = exact_mapping_items(value)
    if items is not None:
        return any(
            exact_contains_fragment(key, needle) or exact_contains_fragment(item, needle)
            for key, item in items
        )
    if type(value) is list or type(value) is tuple or type(value) is set or type(value) is frozenset:
        return any(exact_contains_fragment(item, needle) for item in value)
    return False


def collect_exact_scheduler_evidence(value: object | None) -> tuple[SchedulerEvidenceRecord, ...]:
    source = _exact_evidence_source(value)
    if source is None:
        return collect_scheduler_evidence(value)
    return collect_scheduler_evidence(source)


def _exact_evidence_source(value: object | None) -> object | None:
    if value is None:
        return ()
    if type(value) is SchedulerEvidenceRecord or is_exact_mapping(value):
        return value
    if type(value) is list or type(value) is tuple or type(value) is set or type(value) is frozenset:
        return tuple(
            item
            for item in value
            if type(item) is SchedulerEvidenceRecord or is_exact_mapping(item)
        )
    return None


def exact_mapping_or_none(value: object | None) -> ExactMapping | None:
    if is_exact_mapping(value):
        return cast("ExactMapping", value)
    return None


def is_empty_placeholder(value: object) -> bool:
    if type(value) in {dict, list, tuple, set, frozenset}:
        return len(value) == 0
    return bool(is_exact_mapping(value) and not exact_has_content(value))


__all__ = (
    "collect_exact_scheduler_evidence",
    "exact_contains_fragment",
    "exact_flag",
    "exact_flag_value",
    "exact_has_content",
    "exact_int",
    "exact_int_with_rejection",
    "exact_mapping_items",
    "exact_mapping_or_none",
    "exact_mapping_value",
    "exact_text",
    "first_exact_text",
    "is_empty_placeholder",
    "is_exact_mapping",
)
