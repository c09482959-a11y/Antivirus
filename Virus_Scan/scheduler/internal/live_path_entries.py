"""Live scheduler path-sequence freezing.

Scheduler execution contracts carry owned path identities between scheduler
areas.  These are not final evidence-boundary values: exact text and
pathlib-owned paths are reduced to deterministic text, while unsupported
external objects become explicit scheduler evidence without invoking caller
owned string/path hooks.
"""
from __future__ import annotations

from pathlib import Path, PurePath


from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence


_PATH_TYPES = (type(Path(".")),)


def freeze_live_scheduler_path(value: object) -> object:
    """Return a deterministic scheduler-owned path identity or evidence.

    Unknown objects are rejected rather than stringified. pathlib values are
    accepted only for the exact owned concrete path/PurePath types so hostile
    subclasses cannot override path string conversion.
    """
    if type(value) is str:
        return str.__str__(value)
    if type(value) in _PATH_TYPES or type(value) is PurePath:
        try:
            return PurePath.__str__(value)
        except (RuntimeError, TypeError, ValueError):
            return unsupported_scheduler_value_evidence(value, field_name="scheduler_path")
    text, reason = no_hook_text(
        value,
        missing_reason="missing_scheduler_path",
        unsupported_reason="unsafe_scheduler_path_rejected",
    )
    if not reason and text:
        return text
    return unsupported_scheduler_value_evidence(value, field_name="scheduler_path")


def freeze_live_scheduler_paths(values: object) -> tuple[object, ...]:
    """Freeze a live scheduler path sequence without caller-owned hooks."""
    if values is None:
        return ()
    if type(values) not in {list, tuple}:
        return (unsupported_scheduler_value_evidence(values, field_name="scheduler_paths"),)
    return tuple(freeze_live_scheduler_path(value) for value in no_hook_sequence_items(values))


__all__ = ("freeze_live_scheduler_path", "freeze_live_scheduler_paths")
