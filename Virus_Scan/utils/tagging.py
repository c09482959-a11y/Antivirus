"""Direct-import-safe tag normalization helpers.

These helpers are intentionally pure and do not depend on shared-state
hydration. Modules that only need set/list normalization should import here
instead of expecting detection.tags to be injected into globals.
"""
from __future__ import annotations
import re
from typing import Iterator, Mapping, TYPE_CHECKING

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.contracts.tag_vocabulary import (
    DEFAULT_CANONICAL_TAG_ALIASES,
    DEFAULT_TAG_ALIAS_REPORTING_MAP,
    canonical_synonym_target,
)

PLR2004N80 = 80

if TYPE_CHECKING:
    from collections.abc import Iterable
    TagAliasMapping = Mapping[str, str]

TAG_NORMALIZATION_FAILURE_EVIDENCE = "tag_normalization_failure_evidence"
DETECTION_STAGE_DEGRADED_TAG = "detection_stage_degraded"

def _safe_tag_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_tag_text",
        unsupported_reason="tag_normalization_failure_evidence",
    )
    if reason:
        return TAG_NORMALIZATION_FAILURE_EVIDENCE
    return text


_MAPPING_OBSERVATION_MISSING = object()
_MAPPING_OBSERVATION_TAG_KEYS = ("tag", "behavior", "event", "name", "raw")


def _mapping_observation_tag_value(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return TAG_NORMALIZATION_FAILURE_EVIDENCE
    item_map = {key: item for key, item in items if type(key) is str}
    for key in _MAPPING_OBSERVATION_TAG_KEYS:
        if key not in item_map:
            continue
        raw = item_map[key]
        text = _safe_tag_text(raw).strip()
        if text:
            return raw
    return _MAPPING_OBSERVATION_MISSING


def _append_unique(out: list[str], seen: set[str], text: str) -> None:
    if text and text not in seen:
        seen.add(text)
        out.append(text)


def _failure_markers(out: list[str], seen: set[str]) -> None:
    _append_unique(out, seen, TAG_NORMALIZATION_FAILURE_EVIDENCE)
    _append_unique(out, seen, DETECTION_STAGE_DEGRADED_TAG)


def _iter_tag_values(tags: object) -> Iterator[object] | None:
    if tags is None:
        return iter(())
    if type(tags) is str or type(tags) in (bytes, bytearray, memoryview):
        return iter((tags,))
    items = no_hook_mapping_items(tags)
    if items is not None:
        observation_value = _mapping_observation_tag_value(tags)
        if observation_value is TAG_NORMALIZATION_FAILURE_EVIDENCE:
            return None
        if observation_value is not _MAPPING_OBSERVATION_MISSING:
            return iter((observation_value,))
        return iter(tuple(key for key, _item in items))
    if type(tags) is tuple:
        return iter(tags)
    if type(tags) is list:
        return iter(tuple(tags))
    if type(tags) is set:
        return iter(tuple(tags))
    if type(tags) is frozenset:
        return iter(tuple(tags))
    return None


def _tag_text(tag: object) -> str | None:
    if tag is None:
        return ""
    text = _safe_tag_text(tag)
    return str.strip(text)


def sanitize_tag_part(value: object) -> str:
    return re.sub(r"[^a-z0-9_.:+/-]+", "_", _safe_tag_text(value).strip().lower()).strip("_")


def canonical_reporting_tag(tag: object) -> str:
    low = sanitize_tag_part(tag)
    return DEFAULT_TAG_ALIAS_REPORTING_MAP.get(low, low)


def canonical_tag_name(tag: object) -> str:
    value = sanitize_tag_part(tag)
    if not value:
        return ""
    return canonical_synonym_target(value)


def canonical_raw_tag_name(tag: object) -> str:
    value = _safe_tag_text(tag).strip().lower()
    if not value:
        return ""
    if value.startswith("stage_hit:"):
        return "stage_hit:" + sanitize_tag_part(value.split(":", 1)[1])
    return sanitize_tag_part(value)


def canonical_raw_tag_list(tags: Iterable[object]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    values = _iter_tag_values(tags)
    if values is None:
        return [TAG_NORMALIZATION_FAILURE_EVIDENCE]
    while True:
        try:
            tag = next(values)
        except StopIteration:
            break
        except RECOVERABLE_RUNTIME_ERRORS:
            tag = TAG_NORMALIZATION_FAILURE_EVIDENCE
            values = iter(())
        canonical = canonical_raw_tag_name(tag)
        if canonical and canonical not in seen:
            out.append(canonical)
            seen.add(canonical)
    return out


def canonicalize_event_token(event: object) -> str:
    value = _safe_tag_text(event).strip().lower()
    if not value:
        return ""
    if len(value) <= PLR2004N80 and all(ch.isalnum() or ch in "_:-./" for ch in value):
        return canonical_tag_name(value)
    return value


def ordered_unique_tags(tags: object) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    values = _iter_tag_values(tags)
    if values is None:
        _failure_markers(out, seen)
        return out
    while True:
        try:
            tag = next(values)
        except StopIteration:
            break
        except RECOVERABLE_RUNTIME_ERRORS:
            _failure_markers(out, seen)
            break
        text = _tag_text(tag)
        if text is None:
            _failure_markers(out, seen)
            continue
        if text == TAG_NORMALIZATION_FAILURE_EVIDENCE and type(tag) is not str:
            _failure_markers(out, seen)
            continue
        _append_unique(out, seen, text)
    return out


def normalize_tags(tags: object) -> list[str]:
    return ordered_unique_tags(tags)


def norm_lower_set(tags: object) -> set[str]:
    return {tag.lower() for tag in ordered_unique_tags(tags)}


__all__ = (
    "DEFAULT_CANONICAL_TAG_ALIASES",
    "DEFAULT_TAG_ALIAS_REPORTING_MAP",
    "DETECTION_STAGE_DEGRADED_TAG",
    "TAG_NORMALIZATION_FAILURE_EVIDENCE",
    "canonical_raw_tag_list",
    "canonical_raw_tag_name",
    "canonical_reporting_tag",
    "canonical_tag_name",
    "canonicalize_event_token",
    "norm_lower_set",
    "normalize_tags",
    "ordered_unique_tags",
    "sanitize_tag_part",
)
