"""Canonical content identity boundary for final publication projections.

Final scan-result records publish one authoritative content identity in the exact
``sha256`` field.  Summary projectors use this owner to validate that identity;
they must not derive content identity from paths, aliases, subsystem-local IDs,
or compatibility/fallback fields.
"""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.text_boundaries import exact_bounded_text


def exact_content_sha256(value: object, reason: str) -> str:
    digest = exact_bounded_text(value, reason, maximum=64)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(reason)
    return digest


def final_record_content_sha256(record: object, reason: str) -> str:
    items = no_hook_mapping_items(record)
    if items is None:
        raise TypeError(reason)
    for key, value in items:
        if type(key) is str and str.__eq__(key, "sha256"):
            return exact_content_sha256(value, reason)
    raise ValueError(reason)


__all__ = ("exact_content_sha256", "final_record_content_sha256")
