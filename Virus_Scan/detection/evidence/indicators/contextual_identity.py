"""Contextual identity tag classification ownership.

This module owns the direct translation from canonical routing identity fields
into deterministic detection tags. It does not route files, score evidence,
write reports, or mutate scheduler/runtime state.
"""

from Virus_Scan.detection.tags.heuristics.normalization_runtime import canonical_raw_tag_list
from Virus_Scan.detection.tags.heuristics.vocabulary import sanitize_tag_part as _sanitize_tag_part

CONTEXTUAL_IDENTITY_TAG_MARKERS = frozenset({
    "cross_engine_artifact",
    "engine_mismatch",
    "extension_mismatch",
    "polyglot_artifact",
    "embedded_pe_payload",
    "embedded_zip_payload",
})


def contextual_embedded_type_list(value: object) -> object:
    """Return canonical embedded payload type tokens from routing identity data."""
    if value is None:
        return []
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, (list, tuple, set, frozenset)):
        candidates = list(value)
    else:
        candidates = [value]
    out = []
    seen = set()
    for item in candidates:
        token = str(item).strip().lower()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out



def _append_cross_engine_identity_tags(record: dict[object, object], container: str, artifact: str, tags: list[str]) -> None:
    if bool(record.get("cross_engine_artifact")):
        tags.append("cross_engine_artifact")
        if container and artifact and container != "unknown" and artifact != "unknown":
            tags.append("cross_engine_" + _sanitize_tag_part(container) + "_contains_" + _sanitize_tag_part(artifact))
    if bool(record.get("engine_mismatch")):
        tags.append("engine_mismatch")


def _append_extension_identity_tags(record: dict[object, object], declared: str, sniffed: str, tags: list[str]) -> None:
    if bool(record.get("extension_mismatch")):
        tags.append("extension_mismatch")
        if declared and sniffed and sniffed != "unknown":
            tags.append("declared_" + _sanitize_tag_part(declared.lstrip(".")) + "_sniffs_as_" + _sanitize_tag_part(sniffed))


def _append_embedded_identity_tags(record: dict[object, object], effective: str, tags: list[str]) -> None:
    embedded = contextual_embedded_type_list(record.get("sniffed_embedded_types"))
    if embedded:
        tags.append("polyglot_artifact")
        tags.extend("embedded_" + _sanitize_tag_part(item) + "_payload" for item in embedded[:8])
    if effective in {"embedded_pe_payload", "embedded_zip_payload", "renpy_bytecode", "rpgm_encrypted_asset", "unity_dotnet"}:
        tags.append(effective)


def _append_learning_identity_tag(record: dict[object, object], tags: list[str]) -> None:
    if bool(record.get("learning_allowed")) is False and str(record.get("learning_reason") or ""):
        tags.append("contextual_learning_blocked")


def contextual_identity_reporting_tags(record: object) -> object:
    """Derive canonical reporting tags from contextual identity fields."""
    if not isinstance(record, dict):
        return []
    tags: list[str] = []
    container = str(record.get("container_engine") or "unknown").lower()
    artifact = str(record.get("artifact_engine") or "unknown").lower()
    sniffed = str(record.get("sniffed_type") or "unknown").lower()
    declared = str(record.get("declared_extension") or "").lower()
    effective = str(record.get("effective_analysis_engine") or "unknown").lower()
    _append_cross_engine_identity_tags(record, container, artifact, tags)
    _append_extension_identity_tags(record, declared, sniffed, tags)
    _append_embedded_identity_tags(record, effective, tags)
    _append_learning_identity_tag(record, tags)
    return canonical_raw_tag_list(tags)
