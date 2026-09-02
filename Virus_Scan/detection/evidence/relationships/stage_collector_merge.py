"""Canonical immutable merge owner for raw detection micro-stage outputs."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.detection.models.evidence import StageCollectorMerge
from Virus_Scan.detection.models.stage_value_utils import (
    detection_unavailable_value,
    freeze_mapping_or_empty,
    frozen_tuple_or_empty,
)
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items


def _dedupe_stage_values(values: object) -> tuple[object, ...]:
    if values is None:
        return ()
    out: list[object] = []
    seen: set[str] = set()
    for value in values:
        if type(value) is str:
            text = str.__str__(value)
            if text and text not in seen:
                seen.add(text)
                out.append(text)
            continue
        out.append(value)
    return tuple(out)


def _record_string_items(value: object) -> dict[str, object] | None:
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    return {key: item for key, item in items if type(key) is str}


def _collector_results(results: object) -> tuple[object, ...]:
    if results is None:
        return ()
    items = no_hook_sequence_items(results)
    if items:
        return items
    return (detection_unavailable_value("stage_collector_results_unavailable", results),)


def _stage_name(record: dict[str, object], errors: list[object]) -> str:
    raw_name = dict.get(record, "name")
    if raw_name is None:
        return "stage"
    if type(raw_name) is str:
        name = str.strip(str.__str__(raw_name))
        return name or "stage"
    errors.append(detection_unavailable_value("stage_collector_name_unavailable", raw_name))
    return "stage"


def _extend_stage_tags(tags: list[object], raw_tags: object) -> None:
    tags.extend(frozen_tuple_or_empty(raw_tags))


def _merge_stage_meta(metadata: dict[str, object], name: str, raw_meta: object, errors: list[object]) -> None:
    if raw_meta is None:
        return
    meta_items = no_hook_mapping_items(raw_meta)
    if meta_items is None:
        evidence = detection_unavailable_value("stage_collector_meta_unavailable", raw_meta)
        metadata[name] = evidence
        errors.append(evidence)
        return
    metadata[name] = freeze_mapping_or_empty(dict(meta_items))


def _merge_stage_suspicious(raw_suspicious: object, errors: list[object]) -> bool:
    if raw_suspicious is None:
        return False
    if type(raw_suspicious) is bool:
        return raw_suspicious
    errors.append(detection_unavailable_value("stage_collector_suspicious_unavailable", raw_suspicious))
    return False


def _merge_stage_error(tags: list[object], errors: list[object], name: str, raw_error: object) -> None:
    if raw_error is None:
        return
    if type(raw_error) is str:
        error_text = str.strip(str.__str__(raw_error))
    else:
        errors.append(detection_unavailable_value("stage_collector_error_unavailable", raw_error))
        error_text = "stage_collector_error_unavailable"
    if not error_text:
        return
    errors.append(str.__str__(name) + ":" + error_text)
    tags.append(str.__str__(name) + "_stage_error")


def merge_stage_collector_results(results: object) -> StageCollectorMerge:
    """Merge raw collector outputs without scoring, finalization, or reporting."""
    tags: list[object] = []
    metadata: dict[str, object] = {}
    suspicious = False
    errors: list[object] = []
    for result in _collector_results(results):
        record = _record_string_items(result)
        if record is None:
            errors.append(detection_unavailable_value("stage_collector_record_unavailable", result))
            tags.append("stage_collector_record_unavailable")
            continue
        name = _stage_name(record, errors)
        _extend_stage_tags(tags, dict.get(record, "tags"))
        _merge_stage_meta(metadata, name, dict.get(record, "meta"), errors)
        if _merge_stage_suspicious(dict.get(record, "suspicious"), errors):
            suspicious = True
        _merge_stage_error(tags, errors, name, dict.get(record, "error"))
    return StageCollectorMerge(
        tags=_dedupe_stage_values(tags),
        metadata=MappingProxyType(dict(metadata)),
        suspicious=suspicious,
        errors=_dedupe_stage_values(errors),
    )


__all__ = ("StageCollectorMerge", "merge_stage_collector_results")
