"""No-hook materialization helpers for RPA member behavior boundaries."""

from __future__ import annotations

from types import GeneratorType

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text


def rpa_member_owned_text(value: object, reason: str) -> tuple[str, str]:
    safe_reason = str.__str__(reason) if type(reason) is str else "rpa_member_text_unsafe"
    text, text_reason = no_hook_text(
        value,
        missing_reason=safe_reason,
        unsupported_reason=safe_reason,
    )
    if text_reason:
        return "", text_reason
    return text, ""


def rpa_member_input_path(path: object) -> tuple[str, str]:
    if path is None:
        return "", ""
    return rpa_member_owned_text(path, "rpa_member_path_unsafe")


def rpa_member_payload_bytes(value: object, reason: str) -> tuple[bytes, str]:
    if value is None:
        return b"", reason
    if type(value) is bytes:
        return bytes(value), ""
    if type(value) is bytearray:
        return bytes(value), ""
    if type(value) is memoryview:
        return bytes(value), ""
    return b"", reason


def rpa_member_exact_limited_items(value: object, *, limit: int) -> tuple[object, ...] | None:
    if value is None:
        return ()
    if type(value) is tuple:
        return value[:limit]
    if type(value) is list:
        return tuple(value[:limit])
    if type(value) is GeneratorType:
        out: list[object] = []
        for index, item in enumerate(value):
            if index >= limit:
                break
            out.append(item)
        return tuple(out)
    return None


def mapping_value(value: object, key: str) -> tuple[object, str]:
    items = no_hook_mapping_items(value)
    if items is None:
        return None, "rpa_member_record_unsupported"
    for item_key, item_value in items:
        if type(item_key) is str and item_key == key:
            return item_value, ""
    return None, ""


def meta_failure_reason(meta: object) -> str:
    if meta is None:
        return ""
    value, reason = mapping_value(meta, "failure")
    if reason:
        return "rpa_member_meta_unsafe"
    text, text_reason = rpa_member_owned_text(value, "rpa_member_meta_failure_unsafe")
    if text_reason:
        return ""
    return text


def safe_meta(meta: object) -> tuple[dict[str, object], str]:
    if meta is None:
        return {}, ""
    items = no_hook_mapping_items(meta)
    if items is None:
        return {"failure": "rpa_member_meta_unsafe"}, "rpa_member_meta_unsafe"
    return {key: value for key, value in items if type(key) is str}, ""


__all__ = (
    "mapping_value",
    "meta_failure_reason",
    "rpa_member_exact_limited_items",
    "rpa_member_input_path",
    "rpa_member_owned_text",
    "rpa_member_payload_bytes",
    "safe_meta",
)
