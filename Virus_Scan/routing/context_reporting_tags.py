"""Reporting tag derivation from immutable routing context fields."""
from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import exact_bool_or_none, no_hook_mapping_items, no_hook_sequence_items, no_hook_text
from Virus_Scan.detection.api.routing_vocabulary_contracts import sanitize_tag_part


def _record_items(record: object) -> dict[object, object]:
    items = no_hook_mapping_items(record)
    return {} if items is None else dict(items)


def _record_value(record: dict[object, object], key: str, default: object = None) -> object:
    return dict.get(record, key, default)


def _record_text(record: dict[object, object], key: str, default: str) -> str:
    text, reason = no_hook_text(
        _record_value(record, key),
        missing_reason=str.__add__(key, "_missing"),
        unsupported_reason=str.__add__(key, "_rejected"),
    )
    token = default if reason or text == "" else text.lower().strip()
    return token or default


def _record_flag(record: dict[object, object], key: str) -> bool:
    return exact_bool_or_none(_record_value(record, key, False)) is True


def _tag_text(value: object) -> str:
    text, reason = no_hook_text(value, missing_reason="tag_missing", unsupported_reason="tag_rejected")
    if reason or text == "":
        return ""
    return text.strip().lower()


def _join(parts: tuple[str, ...]) -> str:
    return "".join(parts)


def routing_identity_reporting_tags(record: dict[str, object]) -> list[str]:
    tags = _raw_reporting_tags(record)
    out: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        token = _tag_text(tag)
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    return out


def _raw_reporting_tags(record: dict[str, object]) -> list[str]:
    safe_record = _record_items(record)
    tags: list[str] = []
    container = _record_text(safe_record, "container_engine", "unknown")
    artifact = _record_text(safe_record, "artifact_engine", "unknown")
    sniffed = _record_text(safe_record, "sniffed_type", "unknown")
    declared = _record_text(safe_record, "declared_extension", "")
    effective = _record_text(safe_record, "effective_analysis_engine", "unknown")
    if _record_flag(safe_record, "cross_engine_artifact"):
        tags.append("cross_engine_artifact")
        if container and artifact and container != "unknown" and artifact != "unknown":
            tags.append(_join(("cross_engine_", sanitize_tag_part(container), "_contains_", sanitize_tag_part(artifact))))
    if _record_flag(safe_record, "engine_mismatch"):
        tags.append("engine_mismatch")
    if _record_flag(safe_record, "extension_mismatch"):
        tags.append("extension_mismatch")
        if declared and sniffed and sniffed != "unknown":
            declared_name = declared.removeprefix(".")
            tags.append(_join(("declared_", sanitize_tag_part(declared_name), "_sniffs_as_", sanitize_tag_part(sniffed))))
    tags.extend(
        _join(("embedded_", sanitize_tag_part(embedded), "_payload"))
        for embedded in _embedded_type_list(_record_value(safe_record, "sniffed_embedded_types"))
    )
    if effective in {"embedded_pe_payload", "embedded_zip_payload"}:
        tags.append(effective)
    return tags


def _embedded_type_list(value: object) -> list[str]:
    candidates = no_hook_sequence_items(value)
    return list(
        dict.fromkeys(
            token
            for item in candidates
            if (token := _tag_text(item))
        )
    )
