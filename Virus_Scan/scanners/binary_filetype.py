"""Binary scanner filetype routing and model publication helpers.

This module owns binary scanner filetype context and promotion handoff logic.
It was split out of ``binary.py`` so binary parsing, entropy, and filetype
model state are no longer mixed in one scanner mini-monolith.
"""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items, no_hook_text

from Virus_Scan.scanners.filetype_policy import (
    ENGINE_SPECIFIC_FILETYPE_BUCKETS,
    GLOBAL_COMMON_FILETYPE_BUCKETS,
    HIGH_RISK_BUCKETS,
    NON_EXECUTION_CAPABILITIES,
    PASSIVE_ASSET_CATEGORIES,
    DANGEROUS_ACTUAL_CATEGORIES,
    MAGIC_TYPE_CATEGORY,
)
from Virus_Scan.scanners.binary_path_identity import binary_path_text, normalize_binary_profile_extension

SCANNER_KNOWN_ENGINES = frozenset(ENGINE_SPECIFIC_FILETYPE_BUCKETS) | {"media", "other"}

DANGEROUS_FILETYPE_MISCLASSIFICATION_PAIRS = frozenset(
    (claimed, actual)
    for claimed in PASSIVE_ASSET_CATEGORIES
    for actual in DANGEROUS_ACTUAL_CATEGORIES
)

def _scanner_filetype_text_with_reason(value: object, *, default: str = "") -> tuple[str, str]:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_scanner_filetype_text",
        unsupported_reason="unsafe_scanner_filetype_text_rejected",
    )
    if reason:
        return default, reason
    return text, ""

def _scanner_filetype_text(value: object, *, default: str = "") -> str:
    return _scanner_filetype_text_with_reason(value, default=default)[0]


def _scanner_lower_text(value: object, *, default: str = "") -> str:
    return _scanner_filetype_text(value, default=default).lower()


def _policy_extension_tokens(extensions: object) -> frozenset[str]:
    tokens: set[str] = set()
    for item in no_hook_sequence_items(extensions):
        text = _scanner_filetype_text(item)
        if text:
            tokens.add(text.lower().lstrip('.'))
    return frozenset(tokens)


def _scanner_policy_items(policy: object) -> tuple[tuple[str, object], ...]:
    items = no_hook_mapping_items(policy)
    if items is None:
        return ()
    return tuple((key, value) for key, value in items if type(key) is str)


def _scanner_policy_value(policy: object, key: str) -> object:
    return next((value for item_key, value in _scanner_policy_items(policy) if item_key == key), None)


def _scanner_normalized_ext_token(file_path: object) -> object:
    name = Path(binary_path_text(file_path)).name.lower().strip()
    suffix = Path(name).suffix.lower().lstrip('.')
    if name in {'global-metadata.dat', 'metadata.dat'}:
        return name
    return suffix or '<no_ext>'

def engine_extension_key(engine: object, file_path: object) -> object:
    engine_text = _scanner_lower_text(engine, default='other') or 'other'
    return engine_text + ":" + normalize_binary_profile_extension(file_path)


def _actual_filetype_category(magic_type: object, magic_stage: object = None) -> object:
    mt = _scanner_lower_text(magic_type)
    if mt in MAGIC_TYPE_CATEGORY:
        return MAGIC_TYPE_CATEGORY[mt]
    ms = _scanner_lower_text(magic_stage)
    if ms == 'asset':
        return 'asset'
    if ms in {'binary', 'archive', 'image', 'runtime'}:
        return ms
    return 'unknown'


def _filetype_claim_matches_actual(claimed: object, actual: object, magic_type: object = '') -> object:
    claimed, claimed_reason = _scanner_filetype_text_with_reason(claimed, default='unknown')
    actual, actual_reason = _scanner_filetype_text_with_reason(actual, default='unknown')
    claimed = claimed or 'unknown'
    actual = actual or 'unknown'
    mt = _scanner_lower_text(magic_type)
    if claimed_reason or actual_reason:
        return False
    if claimed == actual:
        return True
    if claimed in PASSIVE_ASSET_CATEGORIES and actual in PASSIVE_ASSET_CATEGORIES:
        return True
    if claimed == 'unity_asset' and actual == 'archive' and mt == 'zip':
        return False
    return False


def _filetype_misclassification_severity(claimed: object, actual: object, magic_type: object = '') -> object:
    claimed, claimed_reason = _scanner_filetype_text_with_reason(claimed, default='unknown')
    actual, actual_reason = _scanner_filetype_text_with_reason(actual, default='unknown')
    claimed = claimed or 'unknown'
    actual = actual or 'unknown'
    mt = _scanner_lower_text(magic_type)
    if claimed_reason or actual_reason:
        return (0, 'none')
    if claimed == 'unknown' or actual == 'unknown' or _filetype_claim_matches_actual(claimed, actual, mt):
        return (0, 'none')
    if (claimed, actual) in DANGEROUS_FILETYPE_MISCLASSIFICATION_PAIRS:
        if actual == 'binary':
            return (24, 'high')
        if actual in {'runtime', 'archive'}:
            return (16, 'medium')
    if claimed in PASSIVE_ASSET_CATEGORIES and actual in DANGEROUS_ACTUAL_CATEGORIES:
        return (16, 'medium')
    return (8, 'low')


def filetype_validation_context(engine: object, file_path: object) -> object:
    global_info = get_global_filetype_info(file_path)
    engine_info = get_engine_filetype_info(engine, file_path)
    active = engine_info if engine_info.get('bucket') != 'unknown_engine' else global_info
    capability = _scanner_lower_text(active.get('execution_capability'), default='unknown') or 'unknown'
    normal = set(global_info.get('normal_buckets', set())) | set(engine_info.get('normal_buckets', set()))
    rare = set(global_info.get('rare_buckets', set())) | set(engine_info.get('rare_buckets', set()))
    high = set(global_info.get('high_risk_buckets', set())) | set(engine_info.get('high_risk_buckets', set()))
    if capability in NON_EXECUTION_CAPABILITIES:
        high |= HIGH_RISK_BUCKETS
    return {'global_bucket': global_info.get('bucket'), 'engine_bucket': engine_info.get('bucket'), 'active_bucket': active.get('bucket'), 'extension': active.get('extension'), 'execution_capability': capability, 'normal_buckets': normal, 'rare_buckets': rare, 'high_risk_buckets': high}


def get_engine_filetype_info(engine: object, file_path: object) -> object:
    engine_key = _scanner_lower_text(engine, default='other') or 'other'
    engine = engine_key if engine_key in SCANNER_KNOWN_ENGINES else "other"
    ext = _scanner_normalized_ext_token(file_path)
    for bucket, info in _scanner_policy_items(_scanner_policy_value(ENGINE_SPECIFIC_FILETYPE_BUCKETS, engine)):
        if ext in _policy_extension_tokens(info.get('extensions', ())):
            out = dict(info)
            out['bucket'] = bucket
            out['extension'] = ext
            return out
    return {'bucket': 'unknown_engine', 'extension': ext, 'execution_capability': 'unknown', 'normal_buckets': set(), 'rare_buckets': set(), 'high_risk_buckets': set()}


def get_global_filetype_info(file_path: object) -> object:
    ext = _scanner_normalized_ext_token(file_path)
    for bucket, info in _scanner_policy_items(GLOBAL_COMMON_FILETYPE_BUCKETS):
        if ext in _policy_extension_tokens(info.get('extensions', ())):
            out = dict(info)
            out['bucket'] = bucket
            out['extension'] = ext
            return out
    return {'bucket': 'unknown_global', 'extension': ext, 'execution_capability': 'unknown', 'normal_buckets': set(), 'rare_buckets': set(), 'high_risk_buckets': set()}


def update_filetype(ext: object, tags: object) -> object:
    """Return an immutable filetype baseline publication request.

    Scanner code must not mutate runtime model state directly. Downstream model
    owners may consume this explicit handoff record and decide whether to update
    model baselines.
    """
    flow_items = []
    for tag in no_hook_sequence_items(tags):
        tag_text = _scanner_filetype_text(tag).strip().lower()
        if tag_text:
            flow_items.append(tag_text)
    flow = tuple(flow_items)
    if not flow:
        return {'updated': False, 'reason': 'no_behavior_flow', 'publication_request': None}
    extension = _scanner_lower_text(ext, default='<no_ext>') or '<no_ext>'
    return {
        'updated': True,
        'extension': extension,
        'flow': flow,
        'publication_request': {
            'kind': 'scanner_filetype_baseline_observation',
            'extension': extension,
            'flow': flow,
        },
    }

__all__ = ("DANGEROUS_FILETYPE_MISCLASSIFICATION_PAIRS", "SCANNER_KNOWN_ENGINES", "_actual_filetype_category", "_filetype_claim_matches_actual", "_filetype_misclassification_severity", "engine_extension_key", "filetype_validation_context", "get_engine_filetype_info", "get_global_filetype_info", "update_filetype")
