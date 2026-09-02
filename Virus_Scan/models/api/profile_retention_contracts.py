"""Public profile-retention model contract.

Profile persistence owns when authoritative profile and staged benign state is committed,
but retention policy owns how those profile-shaped structures are bounded before
commit.  Profile callers use this public boundary instead of importing
``Virus_Scan.models.retention`` implementation internals directly.
"""
from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.api.text_boundary import (
    public_api_contract_text,
    public_duplicate_mapping_key_label,
    public_unavailable_contract_mapping,
    public_unreadable_mapping_key_label,
    public_unreadable_value_label,
)
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from types import MappingProxyType

from Virus_Scan.models.retention import (
    prune_engine_profile_for_retention as owner_prune_engine_profile_for_retention,
    prune_extension_baseline_for_retention as owner_prune_extension_baseline_for_retention,
    prune_staged_benign_store as owner_prune_staged_benign_store,
)


def _detached_retention_text(value: object) -> str:
    """Return exact built-in public-contract text without caller hooks."""
    text, _reason = public_api_contract_text(
        value,
        default_text=public_unreadable_value_label(value),
    )
    return text


def _retention_text_default_text(default_text: object, default: str) -> str:
    if default_text is None:
        return default
    try:
        text = _detached_retention_text(default_text)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return default
    if text == "":
        return default
    return text


def _safe_public_retention_text(value: object, *, default_text: str | None = None) -> str:
    default = default_text if default_text is not None else public_unreadable_value_label(value)
    text, reason = public_api_contract_text(value, default_text=default)
    if reason is not None:
        return text
    if text == "":
        return _retention_text_default_text(default_text, "<blank>")
    return text


def _immutable_retention_value(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        out = {}
        ordered = sorted(
            items,
            key=lambda item: (
                _safe_public_retention_text(no_hook_type_name(item[0])),
                _safe_public_retention_text(item[0], default_text="<unreadable_mapping_key>"),
            ),
        )
        for index, (key, child) in enumerate(ordered):
            key_text = _safe_public_retention_text(key, default_text=public_unreadable_mapping_key_label(index))
            if key_text in out:
                key_text = public_duplicate_mapping_key_label(key_text, index)
            out[key_text] = _immutable_retention_value(child)
        return MappingProxyType(out)
    if isinstance(value, Mapping):
        return public_unavailable_contract_mapping(
            "unsupported_public_mapping",
            evidence_type="profile_retention_public_contract_value_unavailable",
        )
    if type(value) in (list, tuple):
        return tuple(_immutable_retention_value(item) for item in value)
    if type(value) in (set, frozenset):
        try:
            ordered = sorted(value, key=lambda item: (_safe_public_retention_text(no_hook_type_name(item)), _safe_public_retention_text(item)))
        except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
            return ("<unreadable_public_set>",)
        return tuple(_immutable_retention_value(item) for item in ordered)
    if type(value) is str:
        return str.__str__(_safe_public_retention_text(value))
    if type(value) in (int, float, bool) or value is None:
        return value
    _text, _reason = public_api_contract_text(value, default_text=public_unreadable_value_label(value))
    if _reason is not None:
        return public_unavailable_contract_mapping(
            "unreadable_public_contract_text",
            evidence_type="profile_retention_public_contract_value_unavailable",
        )
    return _text




def _retention_mapping_text_safety_evidence(safe: bool, *, ready: bool, reason: str | None) -> Mapping[str, object]:
    degraded = reason is not None
    return _immutable_retention_value({
        "safe": safe,
        "ready": ready,
        "degraded": degraded,
        "unavailable_reason": reason,
        "evidence_type": "profile_retention_mapping_text_safety",
        "final_json_must_record": degraded,
        "replay_record_required": True,
    })


def _retention_safety_flag(evidence: object) -> bool:
    items = no_hook_mapping_items(evidence)
    safe = None
    if items is not None:
        for item_key, item_value in items:
            if type(item_key) is str and str.__eq__(item_key, "safe"):
                safe = item_value
    return safe is True


def _retention_plain_mapping_text_evidence(value: object) -> Mapping[str, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        return _retention_mapping_text_safety_evidence(
            False,
            ready=False,
            reason="profile_retention_mapping_items_unreadable",
        )
    try:
        for key, _child in items:
            _safe_public_retention_text(key)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _retention_mapping_text_safety_evidence(
            False,
            ready=False,
            reason="profile_retention_mapping_key_unreadable",
        )
    return _retention_mapping_text_safety_evidence(True, ready=True, reason=None)


def _retention_plain_mapping_text_safe(value: object) -> bool:
    return _retention_safety_flag(_retention_plain_mapping_text_evidence(value))


def _retention_public_result(value: object) -> object:
    if _retention_plain_mapping_text_safe(value):
        return value
    return _immutable_retention_value(value)


def _retention_mapping_field(value: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__eq__(item_key, key):
            return item_value
    return default


def _retention_is_unavailable_result(value: object) -> bool:
    return (
        _retention_mapping_field(value, "ready") is False
        and _retention_mapping_field(value, "degraded") is True
    )

def _retention_unavailable(reason: str, *, evidence_type: str) -> Mapping[str, object]:
    return _immutable_retention_value({
        "retained": False,
        "ready": False,
        "degraded": True,
        "reason": reason,
        "unavailable_reason": reason,
        "evidence_type": evidence_type,
        "final_json_must_record": True,
        "replay_record_required": True,
    })


def _mapping_is_readable(value: Mapping[str, object]) -> bool:
    return no_hook_mapping_items(value) is not None


def _retention_mapping_or_unavailable(value: object, *, reason: str, evidence_type: str) -> object:
    if type(value) is dict:
        return value
    items = no_hook_mapping_items(value)
    if items is None:
        return _retention_unavailable(reason, evidence_type=evidence_type)
    out = {}
    ordered = sorted(
        items,
        key=lambda item: (
            _safe_public_retention_text(no_hook_type_name(item[0])),
            _safe_public_retention_text(item[0], default_text="<unreadable_mapping_key>"),
        ),
    )
    for index, (key, child) in enumerate(ordered):
        key_text = _safe_public_retention_text(key, default_text=public_unreadable_mapping_key_label(index))
        if key_text in out:
            key_text = public_duplicate_mapping_key_label(key_text, index)
        out[key_text] = _immutable_retention_value(child)
    return out


def prune_engine_profile_for_retention(profile: object) -> object:
    """Apply canonical retention policy to a persisted engine profile."""
    detached = _retention_mapping_or_unavailable(
        profile,
        reason="non_mapping_engine_profile_retention_input",
        evidence_type="profile_retention",
    )
    if _retention_is_unavailable_result(detached):
        return detached
    try:
        return _retention_public_result(owner_prune_engine_profile_for_retention(detached))
    except RECOVERABLE_RUNTIME_ERRORS:
        return _retention_unavailable("engine_profile_retention_failed", evidence_type="profile_retention")


def prune_extension_baseline_for_retention(baseline: object) -> object:
    """Apply canonical retention policy to one extension baseline."""
    detached = _retention_mapping_or_unavailable(
        baseline,
        reason="non_mapping_extension_baseline_retention_input",
        evidence_type="profile_baseline_retention",
    )
    if _retention_is_unavailable_result(detached):
        return detached
    try:
        return _retention_public_result(owner_prune_extension_baseline_for_retention(detached))
    except RECOVERABLE_RUNTIME_ERRORS:
        return _retention_unavailable("extension_baseline_retention_failed", evidence_type="profile_baseline_retention")


def prune_staged_benign_store(store: object) -> object:
    """Apply canonical retention policy to staged benign learning candidates."""
    detached = _retention_mapping_or_unavailable(
        store,
        reason="non_mapping_staged_benign_retention_input",
        evidence_type="profile_staged_benign_retention",
    )
    if _retention_is_unavailable_result(detached):
        return detached
    try:
        return _retention_public_result(owner_prune_staged_benign_store(detached))
    except RECOVERABLE_RUNTIME_ERRORS:
        return _retention_unavailable("staged_benign_retention_failed", evidence_type="profile_staged_benign_retention")


__all__ = (
    "prune_engine_profile_for_retention",
    "prune_extension_baseline_for_retention",
    "prune_staged_benign_store",
)
