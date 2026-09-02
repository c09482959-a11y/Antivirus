"""Canonical no-hook exact string-key mapping item lookup helpers."""
from __future__ import annotations

from collections.abc import Iterable

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items

SchedulerMappingItems = tuple[tuple[object, object], ...]
SchedulerMappingItemsSource = Iterable[tuple[object, object]]


def scheduler_mapping_item_value(
    items: SchedulerMappingItemsSource | None,
    key: str,
    default: object = None,
) -> object:
    """Return the exact-string keyed value from already materialized mapping items."""
    if items is None:
        return default
    if type(key) is not str:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__eq__(item_key, key):
            return item_value
    return default


def first_scheduler_mapping_item_value(
    items: SchedulerMappingItemsSource | None,
    keys: tuple[str, ...],
    default: object = None,
) -> object:
    """Return the first present non-None exact-string keyed mapping item value."""
    missing = object()
    for key in keys:
        item = scheduler_mapping_item_value(items, key, missing)
        if item is not missing and item is not None:
            return item
    return default


def scheduler_mapping_items_tuple(mapping: object) -> SchedulerMappingItems | None:
    """Return no-hook mapping items as an immutable tuple, or None when rejected."""
    items = no_hook_mapping_items(mapping)
    if items is None:
        return None
    return tuple(items)


def scheduler_mapping_value(
    mapping: object,
    key: str,
    default: object = None,
) -> object:
    """Return the exact-string keyed value from a no-hook materialized mapping."""
    return scheduler_mapping_item_value(no_hook_mapping_items(mapping), key, default)


def first_scheduler_mapping_value(
    mapping: object,
    keys: tuple[str, ...],
    default: object = None,
) -> object:
    """Return the first present non-None exact-string keyed mapping value."""
    return first_scheduler_mapping_item_value(no_hook_mapping_items(mapping), keys, default)


def scheduler_str_key_items_from_items(items: SchedulerMappingItemsSource | None) -> tuple[tuple[str, object], ...]:
    """Return exact-string keyed mapping items as an immutable tuple."""
    if items is None:
        return ()
    return tuple((key, item) for key, item in items if type(key) is str)


def scheduler_str_key_mapping_from_items(items: SchedulerMappingItemsSource | None) -> dict[str, object]:
    """Return a plain dict containing only exact-string keys from mapping items."""
    return dict(scheduler_str_key_items_from_items(items))


def scheduler_str_text_mapping_from_items(items: SchedulerMappingItemsSource | None) -> dict[str, str]:
    """Return a plain dict containing only exact string-key/string-value items."""
    if items is None:
        return {}
    return {str.__str__(key): str.__str__(item) for key, item in items if type(key) is str and type(item) is str}


def scheduler_str_sequence_items(value: object) -> tuple[str, ...]:
    """Return exact string items from a no-hook sequence materialization."""
    return tuple(str.__str__(item) for item in no_hook_sequence_items(value) if type(item) is str)


__all__ = (
    "SchedulerMappingItems",
    "SchedulerMappingItemsSource",
    "first_scheduler_mapping_item_value",
    "first_scheduler_mapping_value",
    "scheduler_mapping_item_value",
    "scheduler_mapping_items_tuple",
    "scheduler_mapping_value",
    "scheduler_str_key_items_from_items",
    "scheduler_str_key_mapping_from_items",
    "scheduler_str_sequence_items",
    "scheduler_str_text_mapping_from_items",
)
