"""Extension-mismatch evidence projection for final JSON."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.publication.json_finalization.base_projection import canonical_text_list
from Virus_Scan.publication.json_finalization.projection_text import final_json_mapping_get, present_text
from Virus_Scan.publication.json_finalization.truthiness import (
    boolean_field_true,
    first_present_value,
)


def sniffed_tag_projection_token(record: Mapping[str, object]) -> str:
    """Return the compact tag token for already-recorded sniffed identity.

    This is final JSON projection only. It consumes fields already attached by
    routing/scan ownership and does not re-open files or run a second sniffer.
    """
    declared = present_text(
        first_present_value(record, "declared_extension", "extension")
    ).lower().lstrip(".")
    sniffed = present_text(
        first_present_value(record, "sniffed_type", "sniffed_file_type")
    ).lower()
    if sniffed in ("", "unknown"):
        return declared
    direct = {
        "data": declared,
        "renpy_source": "rpy",
        "renpy_bytecode": "rpyc",
        "python_source": "py",
        "javascript": "js",
        "dotnet_assembly": "dotnet_assembly",
        "pe": "pe",
        "pe_mz": "pe",
        "png": "png",
        "jpg": "jpg",
        "jpeg": "jpeg",
        "webp": "webp",
        "zip": "zip",
        "text": declared if declared != "" else "text",
        "script_text": declared if declared != "" else "script",
    }
    return direct.get(sniffed, sniffed)


def _extension_mismatch_state(
    record: Mapping[str, object],
    tags: object = None,
) -> tuple[bool, str | None, tuple[object, ...]]:
    tag_source = tags if tags is not None else final_json_mapping_get(record, "tags")
    if tag_source is None:
        tag_values: tuple[object, ...] = ()
        unavailable_reason = None
    elif type(tag_source) in (str, bytes, bytearray):
        tag_values = (tag_source,)
        unavailable_reason = None
    elif type(tag_source) is tuple:
        tag_values = tag_source
        unavailable_reason = None
    elif type(tag_source) is list:
        tag_values = tuple(tag_source)
        unavailable_reason = None
    elif type(tag_source) is set:
        tag_values = tuple(tag_source)
        unavailable_reason = None
    elif type(tag_source) is frozenset:
        tag_values = tuple(tag_source)
        unavailable_reason = None
    else:
        tag_values = ()
        unavailable_reason = "extension_mismatch_tags_unavailable"
    if unavailable_reason is not None:
        return True, unavailable_reason, tag_values
    if boolean_field_true(final_json_mapping_get(record, "extension_mismatch", False)):
        return True, None, tag_values
    for tag in tag_values:
        text = present_text(tag).lower()
        if "final_json_text_unavailable" in text:
            return True, "extension_mismatch_tag_text_unavailable", tag_values
        if text in {"extension_mismatch", "extension_magic_type_mismatch"}:
            return True, None, tag_values
        if text.startswith("declared_") and "_sniffs_as_" in text:
            return True, None, tag_values
    return False, None, tag_values


def record_extension_mismatch(
    record: Mapping[str, object],
    tags: list[object] | None = None,
) -> bool:
    """Return the canonical extension mismatch flag for final JSON."""
    mismatch, _unavailable_reason, _tag_values = _extension_mismatch_state(record, tags)
    return mismatch


def extension_mismatch_evidence(
    record: Mapping[str, object],
    tags: list[str],
) -> list[str]:
    """Return deterministic mismatch evidence without changing canonical tags."""
    mismatch, unavailable_reason, tag_values = _extension_mismatch_state(record, tags)
    evidence: list[str] = []
    if not mismatch:
        return evidence
    if unavailable_reason is not None:
        evidence.append(unavailable_reason)
    if "extension_mismatch" in tag_values:
        evidence.append("extension_mismatch")
    declared = present_text(
        first_present_value(record, "declared_extension", "extension")
    ).lower().lstrip(".")
    sniffed = sniffed_tag_projection_token(record).strip().lower()
    if declared != "" and sniffed != "":
        evidence.append("declared_" + declared + "_sniffs_as_" + sniffed)
    return canonical_text_list(evidence, 8, width=256)


__all__ = (
    "extension_mismatch_evidence",
    "record_extension_mismatch",
    "sniffed_tag_projection_token",
)
