"""Truthiness-safe helpers for final JSON publication boundaries."""
from __future__ import annotations

from typing import Mapping
import math

from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_get,
    final_json_mapping_items,
)


def string_or_empty(value: object) -> str:
    if value is None:
        text = ""
    elif type(value) is str:
        text = str.__str__(value)
    elif type(value) is bytes:
        text = bytes.decode(value, "utf-8", errors="replace")
    elif type(value) is bytearray:
        text = bytes.decode(bytes(value), "utf-8", errors="replace")
    elif type(value) is bool:
        text = "true" if value else "false"
    elif type(value) is int:
        text = int.__str__(value)
    elif type(value) is float and math.isfinite(value):
        text = float.__str__(value)
    else:
        text = ""
    return text


def first_present_value(record: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        value = final_json_mapping_get(record, key)
        if value is not None:
            return value
    return None


def boolean_field_true(value: object) -> bool:
    if type(value) is bool:
        return value
    if type(value) is int:
        return value != 0
    if type(value) is float and math.isfinite(value):
        return value != 0.0
    if type(value) is str:
        return str.strip(str.__str__(value)).lower() in {"1", "true", "yes", "y", "on"}
    return False


def signal_present(value: object) -> bool:
    if value is None:
        present = False
    elif isinstance(value, Mapping):
        items = final_json_mapping_items(value)
        present = True if items is None else len(items) > 0
    elif type(value) is list:
        present = list.__len__(value) > 0
    elif type(value) is tuple:
        present = tuple.__len__(value) > 0
    elif type(value) is set:
        present = set.__len__(value) > 0
    elif type(value) is frozenset:
        present = frozenset.__len__(value) > 0
    else:
        present = True
    return present


def any_signal_present(record: Mapping[str, object], *keys: str) -> bool:
    return any(signal_present(final_json_mapping_get(record, key)) for key in keys)


def _plain_instance_values(value: object) -> tuple[object, ...] | None:
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return None
    for field_name in ("_values", "values", "_items", "items"):
        if field_name not in data:
            continue
        candidate = dict.__getitem__(data, field_name)
        if type(candidate) in (list, tuple):
            return tuple(candidate)
        if type(candidate) in (set, frozenset):
            return tuple(sorted(candidate, key=string_or_empty))
    return None


def iterable_values_without_truthiness(value: object) -> list[object]:
    if value is None:
        values: list[object] = []
    elif type(value) is bytes:
        values = [value.decode("utf-8", errors="replace")]
    elif type(value) is str:
        values = [str.__str__(value)]
    elif type(value) is bytearray:
        values = [bytes(value).decode("utf-8", errors="replace")]
    elif type(value) is tuple:
        values = list(value)
    elif type(value) is list:
        values = list(value)
    elif type(value) in (set, frozenset):
        values = sorted(value, key=string_or_empty)
    else:
        direct_values = _plain_instance_values(value)
        values = list(direct_values) if direct_values is not None else []
    return values


__all__ = (
    "any_signal_present",
    "boolean_field_true",
    "first_present_value",
    "iterable_values_without_truthiness",
    "signal_present",
    "string_or_empty",
)
