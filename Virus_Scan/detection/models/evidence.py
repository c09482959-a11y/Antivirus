"""Frozen detection evidence models shared across evidence ownership areas."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.detection.models.stage_value_utils import (
    detection_unavailable_value,
    freeze_detection_value,
    freeze_mapping_or_empty,
    frozen_tuple_or_empty,
    thaw_detection_value,
)
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items


def _unavailable_reason_from_record(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    for key, item in items:
        if key == "unavailable_reason":
            return item
    return None


def _stage_model_text(value: object, replacement: str, reason: str) -> tuple[str, object | None]:
    if value is None:
        return replacement, None
    if type(value) is str:
        text = str.strip(str.__str__(value))
        return (text or replacement), None
    return replacement, detection_unavailable_value(reason, value)


def _stage_model_bool(value: object, replacement: bool, reason: str) -> tuple[bool, object | None]:
    if value is None:
        return replacement, None
    if type(value) is bool:
        return value, None
    return replacement, detection_unavailable_value(reason, value)


@dataclass(frozen=True)
class StageCollectorMerge:
    """Immutable merged output from raw detection micro-stage collectors."""

    tags: tuple[str, ...]
    metadata: object
    suspicious: bool
    errors: tuple[str, ...]

    def __post_init__(self) -> None:
        """Deep-freeze direct constructor values from collector boundaries."""
        frozen_tags = []
        errors = []
        for tag in frozen_tuple_or_empty(self.tags):
            unavailable = _unavailable_reason_from_record(tag)
            if unavailable is not None:
                frozen_tags.append("<unavailable>")
                errors.append({
                    "degraded": True,
                    "unavailable_reason": "stage_collector_tag_unavailable",
                    "source_unavailable_reason": unavailable,
                    "final_json_must_record": True,
                    "replay_record_required": True,
                })
                continue
            tag_text, tag_failure = _stage_model_text(tag, "<unavailable>", "stage_collector_tag_unavailable")
            frozen_tags.append(tag_text)
            if tag_failure is not None:
                errors.append(tag_failure)
        object.__setattr__(self, "tags", tuple(frozen_tags))
        object.__setattr__(self, "metadata", freeze_mapping_or_empty(self.metadata))
        suspicious, suspicious_failure = _stage_model_bool(
            self.suspicious,
            False,
            "stage_collector_suspicious_unavailable",
        )
        if suspicious_failure is not None:
            errors.append(suspicious_failure)
        object.__setattr__(self, "suspicious", suspicious)
        frozen_errors = []
        for error in frozen_tuple_or_empty(self.errors):
            unavailable = _unavailable_reason_from_record(error)
            if unavailable is not None:
                frozen_errors.append("stage_collector_error_unavailable")
                errors.append({
                    "degraded": True,
                    "unavailable_reason": "stage_collector_error_unavailable",
                    "source_unavailable_reason": unavailable,
                    "final_json_must_record": True,
                    "replay_record_required": True,
                })
                continue
            error_text, error_failure = _stage_model_text(error, "stage_collector_error_unavailable", "stage_collector_error_unavailable")
            frozen_errors.append(error_text)
            if error_failure is not None:
                errors.append(error_failure)
        frozen_errors.extend(thaw_detection_value(error) for error in errors)
        object.__setattr__(self, "errors", tuple(freeze_detection_value(frozen_errors)))

    def as_tuple(self) -> object:
        """Expose a mutable-copy tuple for boundary callers without sharing state."""
        return (list(self.tags), thaw_detection_value(self.metadata), self.suspicious, thaw_detection_value(self.errors))


__all__ = ("StageCollectorMerge",)
