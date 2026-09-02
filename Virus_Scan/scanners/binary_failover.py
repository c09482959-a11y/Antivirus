"""Binary scanner failover decision policy."""

from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.binary_failover_evidence import append_binary_failover_evidence
from Virus_Scan.scanners.binary_failover_policy import (
    FAILOVER_MAGIC_STAGES,
    asset_route_already_clean,
    has_route_mismatch,
    renpy_container_without_payload_evidence,
)


_RENPY_TERMINAL_RECOVERABLE_DEFAULT = False
def _binary_failover_text(value: object, *, default: str = '') -> tuple[str, str]:
    if value is None:
        return default, ''
    text, reason = no_hook_text(
        value,
        missing_reason='binary_failover_text_missing',
        unsupported_reason='binary_failover_text_rejected',
    )
    if reason:
        return default, reason
    return text.strip().lower(), ''


def _binary_failover_tag_set(tags: object) -> tuple[frozenset[str], str]:
    if tags is None:
        return frozenset(), ''
    if type(tags) not in (str, bytes, bytearray, tuple, list, set, frozenset):
        return frozenset(), 'binary_failover_tags_rejected'
    values: set[str] = set()
    for item in no_hook_sequence_items(tags):
        text, reason = _binary_failover_text(item)
        if reason:
            return frozenset(), reason
        if text:
            values.add(text)
    return frozenset(values), ''


def _binary_failover_identity_text(identity: object, key: str, *, default: str = 'unknown') -> tuple[str, str]:
    items = no_hook_mapping_items(identity)
    if items is None:
        return default, 'binary_failover_identity_mapping_rejected'
    for item_key, item_value in items:
        if type(item_key) is not str:
            return default, 'binary_failover_identity_key_rejected'
        if str.__str__(item_key) != key:
            continue
        return _binary_failover_text(item_value, default=default)
    return default, ''


def _is_only_filetype_tags(tags: object) -> object:
    """True when scanners produced only benign/common type-identification tags."""
    benign_prefixes = ('filetype_', 'ext_', 'ext_stage_', 'magic_', 'magic_type_', 'observed_stage_', 'actual_stage_', 'claimed_stage_', 'stage_')
    benign_exact = frozenset({'file_seen', 'extension_consistent', 'extension_mismatch', 'extension_untrusted', 'file_empty_or_unreadable', 'archive_file', 'image_file', 'text_file', 'text_config_file', 'script_file', 'pe_file', 'elf_file', 'macho_file', 'native_pe', 'pe_exe', 'pe_dll', 'dll_file', 'archive_member_graph'})
    safe_tags, reason = _binary_failover_tag_set(tags)
    if reason:
        return False
    for tag in safe_tags:
        if tag in benign_exact or str.startswith(tag, benign_prefixes):
            continue
        return False
    return True


def _identity_is_malformed(identity: object, final_tags: object) -> bool:
    if no_hook_mapping_items(identity) is not None:
        return False
    append_binary_failover_evidence(
        final_tags,
        'should_binary_failover_identity',
        TypeError('identity must be an owned mapping'),
        ['binary_failover_identity_malformed', 'scanner_failure'],
        state='malformed',
    )
    return True


def _append_failover_input_evidence(final_tags: object, category: str, reason: str, *, state: str = 'degraded') -> None:
    append_binary_failover_evidence(
        final_tags,
        category,
        TypeError(reason),
        ['binary_failover_identity_malformed', 'scanner_degraded'],
        state=state,
    )


def _renpy_route_is_terminal(identity: object, final_tags: object) -> bool:
    try:
        return renpy_container_without_payload_evidence(identity, _binary_failover_tag_set(final_tags)[0])
    except SCAN_CONTENT_ERRORS as exc:
        append_binary_failover_evidence(
            final_tags,
            'should_binary_failover_renpy_identity',
            exc,
            ['binary_failover_identity_malformed', 'scanner_degraded'],
            state='degraded',
        )
        return _RENPY_TERMINAL_RECOVERABLE_DEFAULT


def _failover_required_by_stage(ext_stage: object, magic_stage: object, mismatch: object, tags_before_common_present: object, final_tags: object) -> bool:
    if ext_stage in {'unknown', 'other'} and magic_stage in {'unknown', 'binary'}:
        return True
    if magic_stage == 'binary':
        return True
    if mismatch and magic_stage in FAILOVER_MAGIC_STAGES:
        return True
    if not tags_before_common_present:
        return True
    return bool(_is_only_filetype_tags(final_tags) and ext_stage in {'unknown', 'other'})


def should_binary_failover(ext_stage: object, effective_stage: object, identity: object, tags_before_common: object, final_tags: object) -> object:
    """Decide whether to run a conservative second binary pass with visible evidence."""
    if _identity_is_malformed(identity, final_tags):
        return True
    final_set, final_tags_reason = _binary_failover_tag_set(final_tags)
    if final_tags_reason:
        _append_failover_input_evidence(final_tags, 'should_binary_failover_tags', final_tags_reason)
        return True
    tags_before_set, tags_before_reason = _binary_failover_tag_set(tags_before_common)
    if tags_before_reason:
        _append_failover_input_evidence(final_tags, 'should_binary_failover_precommon_tags', tags_before_reason)
        return True
    ext_stage_text, ext_stage_reason = _binary_failover_text(ext_stage, default='unknown')
    if ext_stage_reason:
        _append_failover_input_evidence(final_tags, 'should_binary_failover_ext_stage', ext_stage_reason)
        ext_stage_text = 'unknown'
    effective_stage_text, effective_stage_reason = _binary_failover_text(effective_stage, default='unknown')
    if effective_stage_reason:
        _append_failover_input_evidence(final_tags, 'should_binary_failover_effective_stage', effective_stage_reason)
        effective_stage_text = 'unknown'
    magic_stage, magic_reason = _binary_failover_identity_text(identity, 'magic_stage', default='unknown')
    if magic_reason:
        _append_failover_input_evidence(final_tags, 'should_binary_failover_magic_stage', magic_reason)
        return True
    if effective_stage_text == 'binary':
        return False
    if _renpy_route_is_terminal(identity, final_tags):
        return False
    if asset_route_already_clean(effective_stage_text, final_set):
        return False
    return _failover_required_by_stage(
        ext_stage_text,
        magic_stage,
        has_route_mismatch(final_set),
        bool(tags_before_set),
        final_set,
    )


__all__ = ("_is_only_filetype_tags", "should_binary_failover")
