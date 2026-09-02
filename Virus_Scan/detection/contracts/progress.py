"""Detection-owned progress and compatibility-free tag helpers.

Detection stages may describe local stage progress, but they must not mutate the
runtime progress owner directly.  The scheduler/runtime owner decides whether to
consume these immutable observations.
"""

from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import exact_int_or_none, no_hook_text
from Virus_Scan.utils.tagging import ordered_unique_tags


def _progress_text(value: object, default: str = "") -> str:
    """Detach progress text without invoking caller-owned hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_progress_text",
        unsupported_reason="progress_text_rejected",
    )
    if reason or text == "":
        return default
    return text


def _progress_int(value: object) -> int:
    metric = exact_int_or_none(value)
    if metric is None:
        return 0
    return metric


def stage_progress(stage: str = "scan", inc: int = 1, bytes_delta: int = 0) -> MappingProxyType:
    return MappingProxyType({
        "stage": _progress_text(stage, "scan"),
        "inc": _progress_int(inc),
        "bytes_delta": _progress_int(bytes_delta),
        "source": "detection",
    })


def has_any_tag(tags: object, *needles: object) -> bool:
    tag_set = {tag.lower() for tag in ordered_unique_tags(tags)}
    needle_set = {needle.lower() for needle in ordered_unique_tags(needles)}
    return bool(tag_set & needle_set)


__all__ = ("has_any_tag", "stage_progress")
