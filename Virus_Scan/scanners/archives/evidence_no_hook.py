"""No-hook tag/text helpers for archive evidence producers."""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.runtime.api import EXTRACTION_FAILURE
from Virus_Scan.utils.tagging import normalize_tags, sanitize_tag_part

_EXACT_PATH_TYPE = type(Path("."))


def archive_evidence_tags(tags: object) -> list[str]:
    return normalize_tags(tags)


def archive_evidence_text(value: object, reason: str) -> tuple[str, str]:
    if type(value) is _EXACT_PATH_TYPE:
        return _EXACT_PATH_TYPE.__str__(value), ""
    return no_hook_text(value, missing_reason=reason, unsupported_reason=reason)


def archive_evidence_tag(value: object, reason: str) -> str:
    text, text_reason = archive_evidence_text(value, reason)
    if text_reason:
        return reason
    tag = sanitize_tag_part(text)
    return tag or reason


def archive_evidence_path(value: object) -> str:
    text, reason = archive_evidence_text(value, "archive_evidence_path_unsafe")
    return text if not reason else ""


def archive_evidence_present(value: object) -> bool:
    text, reason = archive_evidence_text(value, "archive_evidence_text_unsafe")
    return not reason and bool(text)


def append_unique(tags: list[str], tag: object, *, reason: str = "archive_evidence_tag_unsafe") -> None:
    text = archive_evidence_tag(tag, reason)
    if text and text not in tags:
        tags.append(text)


def append_final_json_marker(tags: list[str]) -> None:
    append_unique(tags, "archive_final_json_must_record")


def with_extraction_failure(tags: object) -> list[str]:
    evidence_tags = archive_evidence_tags(tags)
    append_unique(evidence_tags, EXTRACTION_FAILURE.tag)
    return evidence_tags


__all__ = (
    "append_final_json_marker",
    "append_unique",
    "archive_evidence_path",
    "archive_evidence_present",
    "archive_evidence_tag",
    "archive_evidence_tags",
    "archive_evidence_text",
    "with_extraction_failure",
)
