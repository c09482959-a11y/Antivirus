"""Canonical scan-evidence cache publication snapshot helpers.

Scanner and detection cache-publication handoffs are durable evidence records,
not live runtime cache state.  This module owns the small no-hook boundary used
before those records are published into final JSON / replay-visible metadata.
"""
from __future__ import annotations

from pathlib import PurePath
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    invalid_key_evidence,
    no_hook_duplicate_key,
    no_hook_json_key,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    unsupported_value_evidence,
)

PLR2004N8 = 8

_MAX_CACHE_ITEMS = 256
_MAX_STRINGS_BLOB = 2_000_000
_MAX_RAW_SAMPLE = 512_000


def _scan_cache_evidence(value: object, *, reason: str) -> Mapping[str, object]:
    return MappingProxyType(
        unsupported_value_evidence(value, context="scan_evidence_cache_publication", reason=reason)
    )


def _freeze_scan_cache_value(key: str, value: object, *, depth: int = 0) -> object:
    if depth > PLR2004N8:
        return _scan_cache_evidence(value, reason="scan_cache_depth_limit_exceeded")
    if key == "strings_blob" and isinstance(value, str):
        return str.__str__(value)[:_MAX_STRINGS_BLOB]
    if key == "raw_sample" and type(value) in (bytes, bytearray):
        return bytes(value[:_MAX_RAW_SAMPLE])
    if value is None or type(value) in (bool, int, float):
        return value
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) is bytes:
        return bytes(value[:_MAX_RAW_SAMPLE])
    if type(value) is bytearray:
        return bytes(value[:_MAX_RAW_SAMPLE])
    items = no_hook_mapping_items(value)
    if items is not None:
        if len(items) > _MAX_CACHE_ITEMS:
            return _scan_cache_evidence(value, reason="scan_cache_mapping_size_limit_exceeded")
        keyed: list[tuple[str, int, object, str, object]] = []
        for index, (raw_key, item) in enumerate(items):
            key_text, key_reason = no_hook_json_key(raw_key, index, prefix="scan_cache_key")
            keyed.append((key_text, index, item, key_reason, raw_key))
        out: dict[str, object] = {}
        for raw_key_text, index, item, key_reason, raw_key in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in out:
                key_text = no_hook_duplicate_key(key_text, index)
            if key_reason:
                out[key_text] = MappingProxyType(
                    invalid_key_evidence(raw_key, context="scan_evidence_cache_publication", index=index)
                )
                continue
            out[key_text] = _freeze_scan_cache_value(key_text, item, depth=depth + 1)
        return MappingProxyType(out)
    if type(value) in (tuple, list):
        if len(value) > _MAX_CACHE_ITEMS:
            return _scan_cache_evidence(value, reason="scan_cache_sequence_size_limit_exceeded")
        return tuple(_freeze_scan_cache_value(key, item, depth=depth + 1) for item in value)
    if type(value) in (set, frozenset):
        if len(value) > _MAX_CACHE_ITEMS:
            return _scan_cache_evidence(value, reason="scan_cache_set_size_limit_exceeded")
        frozen = tuple(_freeze_scan_cache_value(key, item, depth=depth + 1) for item in value)
        return tuple(sorted(frozen, key=no_hook_json_sort_key))
    return _scan_cache_evidence(value, reason="unsupported_scan_cache_publication_value")


def scan_evidence_cache_path_text(path: object) -> tuple[str, Mapping[str, object] | None]:
    """Return a deterministic publication path without caller-owned hooks.

    Exact text and pathlib-owned path objects are accepted. Unknown path-like
    objects are not coerced with text or filesystem protocol conversion because those may
    execute caller-owned hooks. Unsupported paths are surfaced as explicit
    evidence so the producer does not silently normalize or stringify them.
    """
    if isinstance(path, str):
        return str.__str__(path), None
    if isinstance(path, PurePath):
        return PurePath.__str__(path), None
    evidence = _scan_cache_evidence(path, reason="unsupported_scan_cache_path")
    return "__unsupported_scan_cache_path__", evidence


def freeze_scan_evidence_cache_items(items: object) -> Mapping[str, object]:
    """Return immutable cache-publication items without caller-owned hooks."""
    mapping_items = no_hook_mapping_items(items)
    if mapping_items is None:
        return MappingProxyType({
            "scan_cache_items_unavailable": _scan_cache_evidence(
                items, reason="unsupported_scan_cache_items_mapping"
            )
        })
    if len(mapping_items) > _MAX_CACHE_ITEMS:
        return MappingProxyType({
            "scan_cache_items_unavailable": _scan_cache_evidence(
                items, reason="scan_cache_items_size_limit_exceeded"
            )
        })
    keyed: list[tuple[str, int, object, str, object]] = []
    for index, (raw_key, value) in enumerate(mapping_items):
        key_text, key_reason = no_hook_json_key(raw_key, index, prefix="scan_cache_item_key")
        keyed.append((key_text, index, value, key_reason, raw_key))
    out: dict[str, object] = {}
    for raw_key_text, index, value, key_reason, raw_key in sorted(keyed, key=lambda row: (row[0], row[1])):
        key_text = raw_key_text
        if key_text in out:
            key_text = no_hook_duplicate_key(key_text, index)
        if key_reason:
            out[key_text] = MappingProxyType(
                invalid_key_evidence(raw_key, context="scan_evidence_cache_publication", index=index)
            )
            continue
        out[key_text] = _freeze_scan_cache_value(key_text, value, depth=0)
    return MappingProxyType(out)


def scan_evidence_cache_item_keys(items: Mapping[str, object]) -> tuple[str, ...]:
    """Return deterministic publication keys for already-frozen cache items."""
    mapping_items = no_hook_mapping_items(items)
    if mapping_items is None:
        return ()
    keys = tuple(key for key, _ in mapping_items if type(key) is str)
    return tuple(sorted(keys, key=lambda item: item))


__all__ = ("freeze_scan_evidence_cache_items", "scan_evidence_cache_item_keys", "scan_evidence_cache_path_text")
