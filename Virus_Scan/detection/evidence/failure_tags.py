"""Detection-owned JSON/replay-visible failure tag helpers."""
from __future__ import annotations

import re

_REJECTED_STAGE_TAG = "unsafe_failure_tag_stage_rejected"
_REJECTED_ERROR_TAG = "unsafe_failure_tag_error_rejected"


def _slug_exact_text(value: object, *, replacement: str) -> tuple[str, str | None]:
    """Return a stable slug without invoking caller-owned hooks.

    Only exact ``str`` values are slugged.  Unknown objects are rejected before
    truthiness, string conversion, formatting, descriptor traversal, or iterable
    materialization can execute.  The optional rejection reason is emitted as a
    tag by the caller so degraded tag-only evidence stays visible.
    """
    if type(value) is str:
        raw = value
    elif value is None:
        raw = replacement
    else:
        raw = replacement
        reason = "unsafe_" + str.__str__(replacement) + "_tag_text_rejected" if type(replacement) is str else _REJECTED_ERROR_TAG
        text = re.sub(r"[^a-zA-Z0-9_]+", "_", raw.strip().lower())
        text = re.sub(r"_+", "_", text).strip("_")
        return text or replacement, reason
    text = re.sub(r"[^a-zA-Z0-9_]+", "_", raw.strip().lower())
    text = re.sub(r"_+", "_", text).strip("_")
    return text or replacement, None


def _failure_category(error: BaseException | str) -> tuple[str, str | None]:
    if isinstance(error, BaseException):
        return _slug_exact_text(type(error).__name__, replacement="recoverable_detection_failure")
    if type(error) is str:
        return _slug_exact_text(error, replacement="recoverable_detection_failure")
    category, reason = _slug_exact_text(None, replacement="recoverable_detection_failure")
    return category, reason or _REJECTED_ERROR_TAG


def failure_tags_for_stage(stage_name: str, error: BaseException | str, *, context: object = "") -> tuple[str, ...]:
    """Return stable failure-evidence tags for tag-only detection boundaries.

    Some enrichment/tag functions can only return tag lists. These tags make
    the degraded state visible to downstream scoring, explainability, JSON, and
    replay without adding an alternate execution path.
    """
    del context  # Explicitly unused contract parameters.
    stage, stage_rejection = _slug_exact_text(stage_name, replacement="detection_stage")
    category, error_rejection = _failure_category(error)
    tags = (
        "detection_stage_degraded",
        "detection_failure_evidence",
        "failure_evidence_recorded",
        str.__str__(stage) + "_degraded",
        str.__str__(stage) + "_" + str.__str__(category),
    )
    rejection_tags = tuple(
        tag
        for tag in (stage_rejection, error_rejection)
        if type(tag) is str and tag
    )
    return tags + rejection_tags


__all__ = ("failure_tags_for_stage",)
