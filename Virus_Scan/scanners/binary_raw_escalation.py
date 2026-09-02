"""Binary scanner raw/deep escalation gate."""

from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.scanners.binary_path_identity import get_binary_scan_extension_with_reason
from Virus_Scan.scanners.binary_runtime_policy import binarydeep_scan_thorough_enabled
from Virus_Scan.scanners.binary_raw_anchors import binary_raw_dangerous_anchor_hits

_RAW_ESCALATION_TAG_PARSE_ERROR = "binary_raw_escalation_tag_parse_error"
_RAW_ESCALATION_EXTENSION_ERROR = "binary_raw_escalation_extension_error"
_RAW_ESCALATION_PREFILTER_ERROR = "binary_raw_escalation_prefilter_error"
_RAW_ESCALATION_SUSPICIOUS_ERROR = "binary_raw_escalation_suspicious_error"


def _raw_escalation_tagset(tags: object) -> object:
    if tags is None:
        return set()
    items = no_hook_sequence_items(tags)
    if not items and type(tags) not in (tuple, list, set, frozenset, str, bytes, bytearray, int, float, bool):
        return {_RAW_ESCALATION_TAG_PARSE_ERROR}
    tagset = set()
    for item in items:
        text, reason = no_hook_text(
            item,
            missing_reason="missing_binary_raw_escalation_tag",
            unsupported_reason="unsafe_binary_raw_escalation_tag_rejected",
        )
        if reason:
            tagset.add(_RAW_ESCALATION_TAG_PARSE_ERROR)
            continue
        normalized = text.strip().lower()
        if normalized:
            tagset.add(normalized)
    return tagset


def _raw_suspicious_is_true(suspicious: object) -> object:
    if type(suspicious) is bool:
        return suspicious
    if type(suspicious) is int:
        return suspicious != 0
    return suspicious is not None


def _prefilter_collection_has_hits(value: object) -> bool:
    if isinstance(value, list) and type(value) is list:
        return len(value) > 0
    if isinstance(value, tuple) and type(value) is tuple:
        return len(value) > 0
    if isinstance(value, set) and type(value) is set:
        return len(value) > 0
    if isinstance(value, frozenset) and type(value) is frozenset:
        return len(value) > 0
    if isinstance(value, dict) and type(value) is dict:
        return len(value) > 0
    return False


def _prefilter_has_hits(prefilter_info: object) -> tuple[bool, str]:
    items = no_hook_mapping_items(prefilter_info)
    if items is None:
        if prefilter_info is None:
            return False, ""
        return False, _RAW_ESCALATION_PREFILTER_ERROR
    values = {key: value for key, value in items if type(key) is str}
    for field in ("hits",):
        value = values.get(field)
        if _prefilter_collection_has_hits(value):
            return True, ""
        if type(value) is bool:
            if value:
                return True, ""
        elif type(value) is int:
            if value != 0:
                return True, ""
        elif value is not None:
            return True, ""
    return False, ""


def _umige_raw_should_escalate_after_triage_inmemory(path: object, tags: object, suspicious: object, prefilter_info: object, curr_stage: object) -> object:
    """Gate expensive raw/deep enrichment behind cheap triage.

    This is deliberately stricter than the old filesystem raw queue. Binary,
    runtime, unknown, .dll, .exe, .py, .rpyc, .js, etc. do NOT escalate merely
    because of type/extension. They need a suspicious prefilter/router signal,
    a dangerous anchor, mismatch, YARA-light hit, explicit asset escalation, or
    thorough mode. Unsupported path/tag/prefilter objects fail open with explicit
    scanner escalation tags instead of executing caller-owned hooks or failing
    closed.
    """
    del curr_stage  # Explicitly unused contract parameters.
    tagset = _raw_escalation_tagset(tags)
    ext, ext_reason = get_binary_scan_extension_with_reason(path)
    if ext_reason:
        ext = ".scanner_ext_error"
        tagset.add(_RAW_ESCALATION_EXTENSION_ERROR)
    if suspicious is not None and type(suspicious) not in (bool, int):
        tagset.add(_RAW_ESCALATION_SUSPICIOUS_ERROR)
    if binarydeep_scan_thorough_enabled():
        return True
    if _raw_suspicious_is_true(suspicious):
        return True
    prefilter_has_hits, prefilter_reason = _prefilter_has_hits(prefilter_info)
    if prefilter_reason:
        tagset.add(prefilter_reason)
    if prefilter_has_hits:
        return True
    escalation_tags = {'asset_deep_scan_escalated', 'extension_magic_type_mismatch', 'asset_extension_magic_mismatch', 'binary_failover', 'router_binary_failover', 'embedded_pe_signature', 'embedded_archive_signature', 'possible_appended_payload', 'asset_embedded_payload_signature', 'yara_hit', 'yaralight_hit', 'packed_or_obfuscated', 'very_high_entropy', 'high_entropy_section', 'pickle_deep_scan_escalated', 'pickle_fast_protocol_hint', 'pickle_fast_base64_protocol_hint', 'pickle_fast_text_hint', 'pickle_fast_exec_context', 'pickle_source_escalation', 'pickle_deserialization_context', _RAW_ESCALATION_TAG_PARSE_ERROR, _RAW_ESCALATION_EXTENSION_ERROR, _RAW_ESCALATION_PREFILTER_ERROR, _RAW_ESCALATION_SUSPICIOUS_ERROR}
    if tagset & escalation_tags:
        return True
    if binary_raw_dangerous_anchor_hits(tagset):
        return True
    high_risk_exts = {'.exe', '.scr', '.sys', '.ps1', '.vbs', '.jse', '.bat', '.cmd'}
    return bool(ext in high_risk_exts and tagset & {'script_execution', 'process_exec', 'encoded_powershell', 'powershell_exec', 'cmd_exec'})


__all__ = ("_umige_raw_should_escalate_after_triage_inmemory",)
