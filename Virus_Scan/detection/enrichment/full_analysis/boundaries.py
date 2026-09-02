"""Truthiness-safe boundary helpers for full-analysis enrichment.

These helpers detach caller-owned containers without using caller truthiness or
implicit empty-result substitutions.  The full-analysis enrichment stage sits between
scanner inputs, model evidence construction, profile context, and final scoring;
when an upstream object has hostile or unreadable truthiness, the stage must not
silently convert that object into clean/default evidence.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.models.stage_value_utils import freeze_detection_value
from Virus_Scan.detection.enrichment.text_boundary import detection_enrichment_text_or_empty


def fa_sequence(value: object) -> tuple[object, ...]:
    """Return a detached tuple without probing caller-owned truthiness."""
    result: tuple[object, ...] = ()
    if value is None:
        return result
    if isinstance(value, (str, bytes)):
        return (value,)
    if isinstance(value, Mapping):
        return result
    if not isinstance(value, Iterable):
        return result
    try:
        result = tuple(value)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        result = ()
    return result


def fa_list(value: object) -> list[object]:
    """Return a mutable list copy for list-consuming callees without ``value or []``."""
    return list(fa_sequence(value))


def fa_mapping_get(mapping: object, key: str, default: object) -> object:
    """Read a mapping field without mapping truthiness or chained ``or``."""
    if not isinstance(mapping, Mapping):
        return default
    value = default
    try:
        value = mapping.get(key, default)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        value = default
    return default if value is None else value


def _unavailable_key_name(index: int) -> str:
    return "<unavailable_key_" + int.__str__(index) + ">"


def fa_mapping(value: object) -> dict[str, object]:
    """Detach a readable mapping without relying on its truthiness."""
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, object] = {}
    keys: tuple[object, ...] = ()
    try:
        keys = tuple(dict.keys(value)) if isinstance(value, dict) else tuple(value)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        keys = ()
    for raw_key in keys:
        key_name = _unavailable_key_name(len(out))
        try:
            item = dict.__getitem__(value, raw_key) if isinstance(value, dict) else value[raw_key]
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
            item = freeze_detection_value({
                "degraded": True,
                "unavailable_reason": "full_analysis_mapping_value_unavailable",
                "field": detection_enrichment_text_or_empty(raw_key, default=key_name),
                "final_json_must_record": True,
                "replay_record_required": True,
            })
        key_text = detection_enrichment_text_or_empty(raw_key, default=key_name)
        out[key_text] = item
    return out


def fa_text(value: object, default: str = "") -> str:
    """Return text without ``value or ''`` fallbacks."""
    return detection_enrichment_text_or_empty(value, default=default)


def fa_callable_or_default(value: object, default: object) -> object:
    """Select an optional callable without invoking caller truthiness."""
    return default if value is None else value


__all__ = (
    "fa_callable_or_default",
    "fa_list",
    "fa_mapping",
    "fa_mapping_get",
    "fa_sequence",
    "fa_text",
)
