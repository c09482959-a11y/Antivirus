"""Decoded payload tag projection for scanner text and string domains."""
from __future__ import annotations


from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.scanners.contracts import scanner_contract_join, scanner_contract_text, scanner_failure_evidence_tags
from Virus_Scan.scanners.payload.behavior import decoded_payload_behavior_tags
from Virus_Scan.scanners.payload.decode import safe_decode_payloads

def _payload_record_get(record: object, key: object, default: object = None) -> object:
    items = no_hook_mapping_items(record)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__str__(item_key) == key:
            return item_value
    return default

def decoded_payload_tags(strings_blob: object, path: object = None, *, finalize: bool = True) -> list[str]:
    """Scanner-owned decoded-payload tag projection.

    This keeps scanner domains from importing detection contextual decoding helpers.
    It derives payload evidence from the canonical scanner payload decoder and
    behavior classifier only; detection may add contextual rescanning later.
    """
    tags: list[str] = []
    try:
        for rec in no_hook_sequence_items(safe_decode_payloads(scanner_contract_text(strings_blob))):
            tags.extend(decoded_payload_behavior_tags(rec, []))
            encoding = scanner_contract_text(_payload_record_get(rec, "encoding", "encoded"), replacement="encoded") or "encoded"
            binary_magic = scanner_contract_text(_payload_record_get(rec, "binary_magic", ""))
            if binary_magic:
                tags.extend(["payload_decode_candidate", "decoded_binary_payload", scanner_contract_join("decoded_", binary_magic, "_payload")])
            if tags and _payload_record_get(rec, "text"):
                tags.extend(["payload_decode_candidate", scanner_contract_join("decoded_", encoding, "_payload"), "decoded_payload_rescanned"])
    except SCAN_CONTENT_ERRORS as exc:
        tags.extend(scanner_failure_evidence_tags(
            "payload_decode",
            "decoded_payload_tags",
            exc,
            ["decoded_payload_failure_evidence", "scanner_degraded"],
            input_path=path,
            state="degraded",
            error_category="payload_decode_failure",
        ))
    if finalize:
        out: list[str] = []
        for tag in tags:
            value = scanner_contract_text(tag)
            if value not in out:
                out.append(value)
        return out
    return list(tags)

__all__ = ("decoded_payload_tags",)
