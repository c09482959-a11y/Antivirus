"""No-hook helpers for archive member payload evidence boundaries."""

from __future__ import annotations

from pathlib import Path
from types import GeneratorType

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.utils.tagging import sanitize_tag_part
from Virus_Scan.scanners.archives.text_boundaries import archive_delimited_join

_EXACT_PATH_TYPE = type(Path("."))


def archive_payload_text(value: object, reason: str) -> tuple[str, str]:
    return no_hook_text(value, missing_reason=reason, unsupported_reason=reason)


def archive_payload_path(path: object) -> str:
    if type(path) is _EXACT_PATH_TYPE:
        return _EXACT_PATH_TYPE.__str__(path)
    text, reason = archive_payload_text(path, "archive_member_payload_path_unsafe")
    return text if not reason else ""


def archive_payload_items(value: object, *, limit: int) -> tuple[object, ...] | None:
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


def archive_payload_mapping_value(value: object, key: str) -> tuple[object, str]:
    items = no_hook_mapping_items(value)
    if items is None:
        return None, "archive_member_payload_record_unsupported"
    for item_key, item_value in items:
        if type(item_key) is str and item_key == key:
            return item_value, ""
    return None, ""


def archive_payload_record_mapping(value: object) -> tuple[dict[str, object], str]:
    items = no_hook_mapping_items(value)
    if items is None:
        return {}, "archive_member_payload_record_unsupported"
    return {key: item for key, item in items if type(key) is str}, ""


def archive_payload_behavior_record(value: object) -> tuple[dict[str, object], tuple[str, ...]]:
    record, reason = archive_payload_record_mapping(value)
    if reason:
        return {}, (reason,)
    out: dict[str, object] = {}
    failures: list[str] = []
    for key in ("encoding", "text", "binary_magic"):
        item = dict.get(record, key)
        text, text_reason = archive_payload_text(item, archive_delimited_join("_", "archive_member_payload", key, "unsafe"))
        if text_reason:
            if item is not None:
                failures.append(text_reason)
            continue
        if text:
            out[key] = text
    chain = dict.get(record, "decode_chain")
    chain_items = archive_payload_items(chain, limit=16)
    if chain_items is None:
        if chain is not None:
            failures.append("archive_member_payload_decode_chain_unsafe")
    else:
        safe_chain: list[str] = []
        for item in chain_items:
            text, text_reason = archive_payload_text(item, "archive_member_payload_decode_chain_item_unsafe")
            if text_reason:
                failures.append(text_reason)
                continue
            if text:
                safe_chain.append(text)
        if safe_chain:
            out["decode_chain"] = tuple(safe_chain)
    return out, tuple(failures)


def archive_payload_magic_tag(value: object) -> tuple[str, str]:
    text, reason = archive_payload_text(value, "archive_member_payload_binary_magic_unsafe")
    if reason:
        return "binary", reason
    tag = sanitize_tag_part(text)
    return (tag or "binary"), ""


__all__ = (
    "archive_payload_behavior_record",
    "archive_payload_items",
    "archive_payload_magic_tag",
    "archive_payload_mapping_value",
    "archive_payload_path",
    "archive_payload_record_mapping",
    "archive_payload_text",
)
