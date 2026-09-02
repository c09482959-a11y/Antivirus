"""Archive-owned RPA decoded-member behavior evidence boundary."""

from __future__ import annotations

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.contracts.scanner_evidence import scanner_failure_evidence_tags
from Virus_Scan.scanners.api.payload_contracts import embedded_payload_records_from_bytes
from Virus_Scan.scanners.api.pickle_contracts import (
    iter_pickle_payload_records,
    iter_renpy_rpa_members,
    iter_rpyc_pickle_byte_views,
)
from Virus_Scan.scanners.archives.rpa_member_no_hook import (
    mapping_value,
    meta_failure_reason,
    rpa_member_input_path,
    rpa_member_exact_limited_items,
    safe_meta as materialize_meta,
    rpa_member_payload_bytes,
    rpa_member_owned_text,
)
from Virus_Scan.scanners.archives.rpa_member_text_tags import append_behavior_tags
from Virus_Scan.utils.tagging import normalize_tags, ordered_unique_tags
from Virus_Scan.scanners.archives.text_boundaries import archive_colon_join

_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_DECODED_BYTES = _PICKLE_POLICY.decode_max_decoded_bytes
PICKLE_DECODE_MAX_FILE_BYTES = _PICKLE_POLICY.decode_max_file_bytes
def _decode_payload_text(payload: bytes) -> list[str]:
    text_views: list[str] = []
    for enc in ("utf-8", "latin1"):
        try:
            text = bytes(payload[:PICKLE_DECODE_MAX_DECODED_BYTES]).decode(enc, errors="ignore")
        except SCAN_CONTENT_ERRORS:
            text_views.append("rpa_member_text_decode_failure")
            continue
        if text:
            text_views.append(text)
            break
    return text_views


def _append_rpa_member_failure(tags: list[str], error: BaseException | str, stage: str, input_path: str) -> None:
    tags.extend(scanner_failure_evidence_tags(
        "archive_rpa", stage, error, ["rpa_member_parse_failure", "rpa_member_decode_failure"],
        input_path=input_path, error_category="rpa_member_boundary_failure",
        error_source=archive_colon_join("archives.rpa_member_behavior", stage), file_type="rpa",
    ))
    tags.extend(["rpa_failure_evidence_recorded", "archive_final_json_must_record"])


def _iter_member_views(data: bytes, path: str | None) -> object:
    blob = bytes(data[:PICKLE_DECODE_MAX_FILE_BYTES])
    if not blob:
        return
    members = rpa_member_exact_limited_items(iter_renpy_rpa_members(blob, path=path), limit=96)
    if members is None:
        yield "rpa_member:view_sequence_unsafe", b"", {"failure": "rpa_member_view_sequence_unsafe"}
        return
    for member_name, payload, meta in members:
        meta_failure = meta_failure_reason(meta)
        payload_blob, payload_reason = rpa_member_payload_bytes(payload, "rpa_member_payload_unsafe")
        member_text, member_reason = rpa_member_owned_text(member_name, "rpa_member_name_unsafe")
        if meta_failure:
            yield "rpa_member:metadata_failure", payload_blob, {"failure": meta_failure}
            continue
        if member_reason:
            yield "rpa_member:unsafe_member_name", payload_blob, {"failure": member_reason}
            continue
        safe_member = member_text.replace("\\", "/")[:512]
        if payload_reason:
            yield "rpa_member:" + safe_member, b"", {"failure": payload_reason}
            continue
        meta_record, meta_reason = materialize_meta(meta)
        if meta_reason:
            yield "rpa_member:" + safe_member, payload_blob, meta_record
            continue
        yield "rpa_member:" + safe_member, payload_blob, meta_record
        if safe_member.lower().endswith((".rpyc", ".rpyb", ".rpymc", ".rpy", ".rpym")):
            yield from _iter_safe_subviews(safe_member, payload_blob)


def _iter_safe_subviews(safe_member: str, payload_blob: bytes) -> object:
    sub_views = rpa_member_exact_limited_items(iter_rpyc_pickle_byte_views(payload_blob, path=safe_member), limit=32)
    if sub_views is None:
        yield "rpa_member:" + safe_member + "::unsafe_subview", b"", {"failure": "rpa_member_subview_sequence_unsafe"}
        return
    for sub_kind, sub_payload in sub_views:
        sub_text, sub_reason = rpa_member_owned_text(sub_kind, "rpa_member_subkind_unsafe")
        sub_blob, sub_payload_reason = rpa_member_payload_bytes(sub_payload, "rpa_member_subpayload_unsafe")
        if sub_reason or sub_payload_reason:
            yield "rpa_member:" + safe_member + "::unsafe_subview", b"", {"failure": sub_reason or sub_payload_reason}
            continue
        yield "rpa_member:" + safe_member + "::" + sub_text, sub_blob, {}


def _append_record_text(text_views: list[str], rec: object) -> None:
    value, reason = mapping_value(rec, "text")
    if reason:
        text_views.append("rpa_member_record_unsupported")
        return
    text, text_reason = rpa_member_owned_text(value, "rpa_member_record_text_unsafe")
    if text_reason:
        if value is not None:
            text_views.append(text_reason)
        return
    if text:
        text_views.append(text)


def _payload_text_views(payload: bytes) -> list[str]:
    text_views = _decode_payload_text(payload)
    try:
        records = rpa_member_exact_limited_items(iter_pickle_payload_records(payload), limit=16)
        if records is None:
            text_views.append("rpa_pickle_payload_record_failure")
        else:
            for rec in records:
                _append_record_text(text_views, rec)
    except SCAN_CONTENT_ERRORS:
        text_views.append("rpa_pickle_payload_record_failure")
    try:
        records = rpa_member_exact_limited_items(embedded_payload_records_from_bytes(payload, encoding_hint="renpy_rpa_member", max_offsets=16), limit=16)
        if records is None:
            text_views.append("rpa_embedded_payload_record_failure")
        else:
            for rec in records:
                _append_record_text(text_views, rec)
                failure_tags, failure_reason = mapping_value(rec, "failure_tags")
                if not failure_reason:
                    text_views.extend(normalize_tags(failure_tags))
    except SCAN_CONTENT_ERRORS:
        text_views.append("rpa_embedded_payload_record_failure")
    return text_views



def rpa_decoded_member_behavior_tags(data: object = None, path: object = None) -> list[str]:
    """Return deterministic evidence tags for decoded RPA/RPYC member behavior."""
    tags: list[str] = []
    try:
        input_path, input_path_reason = rpa_member_input_path(path)
        if input_path_reason:
            _append_rpa_member_failure(tags, input_path_reason, "rpa_member_path", input_path)
        blob, blob_reason = rpa_member_payload_bytes(data, "rpa_member_input_unsafe")
        blob = bytes(blob[:PICKLE_DECODE_MAX_FILE_BYTES])
        if blob_reason:
            _append_rpa_member_failure(tags, blob_reason, "rpa_member_decode", input_path)
            return ordered_unique_tags(tags)
        if not blob:
            return ordered_unique_tags(tags)
        for _kind, payload, meta in _iter_member_views(blob, input_path):
            failure_reason = meta_failure_reason(meta)
            if failure_reason:
                _append_rpa_member_failure(tags, failure_reason, "rpa_member_parse", input_path)
                continue
            for text in _payload_text_views(payload)[:24]:
                append_behavior_tags(tags, text)
    except SCAN_CONTENT_ERRORS as exc:
        _append_rpa_member_failure(tags, exc, "rpa_member_decode", "")
    return ordered_unique_tags(tags)


__all__ = ("rpa_decoded_member_behavior_tags",)
