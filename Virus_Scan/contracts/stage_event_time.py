"""Shared deterministic stage-event time contract.

Stage-event records can be replay evidence.  When no scan-owned captured
clock value is supplied, callers use this stable content digest instead of
reading wall-clock time in model/detection publication paths.
"""
from __future__ import annotations

import hashlib
from typing import Iterable

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name


def _stage_time_text(value: object, *, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_stage_event_time_text",
        unsupported_reason="unsafe_stage_event_time_text_value_rejected",
    )
    if reason:
        return default
    return text


def _stage_time_tag_values(tags: Iterable[object]) -> tuple[object, ...]:
    if tags is None:
        return ()
    if isinstance(tags, str):
        return (tags,)
    if type(tags) in (tuple, list):
        return tuple(tags)
    if type(tags) in (set, frozenset):
        materialized = tuple(tags)
        return tuple(sorted(materialized, key=lambda item: (_stage_time_text(no_hook_type_name(item)), _stage_time_text(item))))
    return ("stage_event_tags_unavailable",)


def deterministic_stage_event_time(file: object, stage: str, tags: Iterable[object]) -> float:
    """Return a stable numeric event-time surrogate for equivalent inputs."""
    normalized_tags = tuple(_stage_time_text(tag, default="stage_event_tag_unavailable") for tag in _stage_time_tag_values(tags))
    material = "\x1f".join((
        _stage_time_text(file, default="stage_event_file_unavailable"),
        _stage_time_text(stage, default="stage_event_stage_unavailable"),
        "\x1e".join(normalized_tags),
    ))
    digest = hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()
    return int(digest[:12], 16) / float(16 ** 12)
