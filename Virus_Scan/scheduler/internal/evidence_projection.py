"""No-hook text and path projection for scheduler evidence fields."""
from __future__ import annotations

from pathlib import Path, PurePath


from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name

_PATH_TYPES = (type(Path(".")),)


def _scheduler_field_text(field_name: object, *, owner: str) -> str:
    if type(field_name) is str and field_name:
        return str.__str__(field_name)
    return owner




def scheduler_evidence_text(
    value: object,
    *,
    missing_text: str,
    field_name: str,
) -> str:
    """Return exact text or an explicit rejection marker for evidence fields."""
    text, reason = no_hook_text(
        value,
        missing_reason="scheduler_text_missing",
        unsupported_reason=str.__add__(
            "unsupported_",
            _scheduler_field_text(field_name, owner="scheduler_text"),
        ),
    )
    if reason and value is not None:
        return "<" + no_hook_type_name(value) + " " + reason + ">"
    if text:
        return text
    if type(missing_text) is str:
        return str.__str__(missing_text)
    return "scheduler_text_missing"


def scheduler_evidence_path(
    value: object,
    *,
    field_name: str = "scheduler_path",
) -> str:
    """Return an exact path or an explicit rejection marker."""
    field_text = _scheduler_field_text(field_name, owner="scheduler_path")
    if value is None:
        return "missing_" + field_text
    if type(value) is str:
        return str.__str__(value)
    if type(value) in _PATH_TYPES or type(value) is PurePath:
        try:
            return PurePath.__str__(value)
        except (RuntimeError, TypeError, ValueError):
            reason = str.__add__("unsupported_", _scheduler_field_text(field_text, owner="scheduler_path"))
            return "<" + no_hook_type_name(value) + " " + reason + ">"
    reason = str.__add__("unsupported_", _scheduler_field_text(field_text, owner="scheduler_path"))
    return "<" + no_hook_type_name(value) + " " + reason + ">"


__all__ = ("scheduler_evidence_path", "scheduler_evidence_text")
