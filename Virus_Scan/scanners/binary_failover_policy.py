"""Binary failover routing policy helpers."""

from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)

RENpy_ARCHIVE_EXTENSIONS = frozenset({'.rpyc', '.rpyb', '.rpymc', '.rpa'})
PAYLOAD_EVIDENCE_TAGS = frozenset({'embedded_pe_signature', 'embedded_pe_header_truncated', 'embedded_pe_signature_missing', 'embedded_zip_signature', 'embedded_7z_signature', 'embedded_rar_signature', 'extension_magic_type_mismatch'})
ASSET_CLEAN_TAGS = frozenset({'asset_fast_triage_clean', 'unity_container_fast_triage_clean'})
MISMATCH_TAGS = frozenset({'extension_mismatch', 'extension_untrusted', 'filetype_misclassification'})
FAILOVER_MAGIC_STAGES = frozenset({'binary', 'archive', 'runtime', 'asset', 'image'})


def _binary_failover_policy_text(value: object, *, default: str = '') -> tuple[str, str]:
    """Return scanner policy text without caller-owned conversions."""
    if value is None:
        return default, ''
    text, reason = no_hook_text(
        value,
        missing_reason='binary_failover_policy_text_missing',
        unsupported_reason='binary_failover_policy_text_rejected',
    )
    if reason:
        return default, reason
    return text.strip().lower(), ''


def _binary_failover_policy_tag_set(tags: object) -> tuple[frozenset[str], str]:
    """Return exact tag strings without caller-owned iteration or stringification."""
    if tags is None:
        return frozenset(), ''
    if type(tags) not in (str, bytes, bytearray, tuple, list, set, frozenset):
        return frozenset(), 'binary_failover_policy_tags_rejected'
    values: set[str] = set()
    for item in no_hook_sequence_items(tags):
        text, reason = no_hook_text(
            item,
            missing_reason='binary_failover_policy_tag_missing',
            unsupported_reason='binary_failover_policy_tag_rejected',
        )
        if reason:
            return frozenset(), reason
        if text:
            values.add(text.strip().lower())
    return frozenset(values), ''


def _binary_failover_identity_text(identity: object, key: str, *, default: str = '') -> tuple[str, str]:
    items = no_hook_mapping_items(identity)
    if items is None:
        return default, 'binary_failover_identity_mapping_rejected'
    for item_key, item_value in items:
        if type(item_key) is not str:
            return default, 'binary_failover_identity_key_rejected'
        if str.__str__(item_key) != key:
            continue
        return _binary_failover_policy_text(item_value, default=default)
    return default, ''


def has_route_mismatch(final_set: set[str] | frozenset[str]) -> bool:
    safe_tags, reason = _binary_failover_policy_tag_set(final_set)
    if reason:
        return True
    return bool(safe_tags & MISMATCH_TAGS)


def renpy_container_without_payload_evidence(identity: dict, final_set: set[str] | frozenset[str]) -> bool:
    safe_tags, tag_reason = _binary_failover_policy_tag_set(final_set)
    if tag_reason:
        raise TypeError(tag_reason)
    actual_ext, ext_reason = _binary_failover_identity_text(identity, 'ext')
    if ext_reason:
        raise TypeError(ext_reason)
    magic_type, magic_reason = _binary_failover_identity_text(identity, 'magic_type')
    if magic_reason:
        raise TypeError(magic_reason)
    if actual_ext in RENpy_ARCHIVE_EXTENSIONS and not safe_tags & PAYLOAD_EVIDENCE_TAGS:
        return True
    return magic_type == 'renpy_rpyc' and not safe_tags & PAYLOAD_EVIDENCE_TAGS


def asset_route_already_clean(effective_stage: str, final_set: set[str] | frozenset[str]) -> bool:
    stage, stage_reason = _binary_failover_policy_text(effective_stage)
    if stage_reason or stage != 'asset':
        return False
    safe_tags, tag_reason = _binary_failover_policy_tag_set(final_set)
    if tag_reason:
        return False
    if 'extension_mismatch' in safe_tags or 'asset_deep_scan_escalated' in safe_tags:
        return False
    return bool(safe_tags & ASSET_CLEAN_TAGS)


__all__ = (
    'FAILOVER_MAGIC_STAGES',
    'asset_route_already_clean',
    'has_route_mismatch',
    'renpy_container_without_payload_evidence',
)
