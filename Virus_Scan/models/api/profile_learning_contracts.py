"""Public profile-learning model contract.

Replay learning reconstructs parent-side model observations, but profile schema,
behavior-flow projection, filetype baseline learning, vector projection, and
clean-learning commits remain owned by the profile model implementation.  Other
model subdomains use this bounded public API instead of importing
``Virus_Scan.models.profiles.api`` internals directly.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.models.api.text_boundary import (
    public_api_contract_text,
    public_duplicate_mapping_key_label,
    public_first_unavailable_reason,
    public_unavailable_contract_mapping,
    public_unreadable_mapping_key_label,
    public_unreadable_value_label,
)
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.models.profiles.commit import (
    commit_promoted_learning as owner_commit_promoted_learning,
)
from Virus_Scan.models.profiles.learning import (
    behavior_vector_from_scan as owner_behavior_vector_from_scan,
    canonical_behavior_flow_from_sources as owner_canonical_behavior_flow_from_sources,
    learning_verdict_is_clean as owner_learning_verdict_is_clean,
)
from Virus_Scan.models.profiles.persistence import DEFAULT_ENGINES as owner_DEFAULT_ENGINES


DEFAULT_ENGINES = tuple(owner_DEFAULT_ENGINES)


def _detached_profile_learning_text(value: object) -> str:
    """Return exact built-in public profile-learning text without caller hooks."""
    text, _reason = public_api_contract_text(
        value,
        default_text=public_unreadable_value_label(value),
    )
    return text


def _profile_learning_text_default_text(default_text: object, default: str) -> str:
    if default_text is None:
        return default
    try:
        text = _detached_profile_learning_text(default_text)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return default
    if text == "":
        return default
    return text


def _safe_public_profile_learning_text(value: object, *, default_text: str | None = None) -> str:
    default = default_text if default_text is not None else public_unreadable_value_label(value)
    text, reason = public_api_contract_text(value, default_text=default)
    if reason is not None:
        return text
    if text == "":
        return _profile_learning_text_default_text(default_text, "<blank>")
    return text


def _immutable_profile_learning_value(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        out = {}
        keyed = []
        for index, (key, child) in enumerate(items):
            key_text = _safe_public_profile_learning_text(key, default_text=public_unreadable_mapping_key_label(index))
            keyed.append((key_text, index, child))
        for raw_key_text, index, child in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in out:
                key_text = public_duplicate_mapping_key_label(key_text, index)
            out[key_text] = _immutable_profile_learning_value(child)
        return MappingProxyType(out)
    if isinstance(value, Mapping):
        return public_unavailable_contract_mapping(
            "unsupported_public_mapping",
            evidence_type="profile_learning_public_contract_value_unavailable",
        )
    if type(value) in (list, tuple):
        return tuple(_immutable_profile_learning_value(item) for item in value)
    if type(value) in (set, frozenset):
        try:
            ordered = sorted(value, key=lambda item: (_safe_public_profile_learning_text(no_hook_type_name(item)), _safe_public_profile_learning_text(item)))
        except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
            return ("<unreadable_public_set>",)
        return tuple(_immutable_profile_learning_value(item) for item in ordered)
    if type(value) is str:
        return str.__str__(_safe_public_profile_learning_text(value))
    if type(value) in (int, float, bool) or value is None:
        return value
    _text, _reason = public_api_contract_text(value, default_text=public_unreadable_value_label(value))
    if _reason is not None:
        return public_unavailable_contract_mapping(
            "unreadable_public_contract_text",
            evidence_type="profile_learning_public_contract_value_unavailable",
        )
    return _text


def _public_profile_learning_sequence(value: object) -> tuple[tuple[object, ...], str | None]:
    if value is None:
        return (), None
    if type(value) in (str, bytes, bytearray, bool, int, float):
        return (value,), None
    if no_hook_mapping_items(value) is not None:
        return (value,), None
    if isinstance(value, Mapping):
        return (), "unsupported_profile_learning_public_mapping_sequence"
    if type(value) in (tuple, list, set, frozenset):
        return tuple(value), None
    return (), "non_iterable_profile_learning_public_sequence"


def _profile_learning_unavailable(reason: str, *, evidence_type: str = "profile_learning_public_contract") -> Mapping[str, object]:
    return _immutable_profile_learning_value({
        "learned": False,
        "promoted": False,
        "updated": False,
        "ready": False,
        "degraded": True,
        "reason": reason,
        "unavailable_reason": reason,
        "evidence_type": evidence_type,
        "final_json_must_record": True,
        "replay_record_required": True,
    })


def canonical_behavior_flow_from_sources(
    *,
    raw_tags: object = None,
    ordered_events: object = None,
    behavior_timeline: object = None,
    behavior_flow: object = None,
) -> object:
    """Canonicalize replay/profile behavior flow through the profile owner."""
    raw_tag_values, _raw_reason = (
        (raw_tags, None)
        if type(raw_tags) is TagEvidence
        else _public_profile_learning_sequence(raw_tags)
    )
    ordered_event_values, _event_reason = _public_profile_learning_sequence(ordered_events)
    timeline_values, _timeline_reason = _public_profile_learning_sequence(behavior_timeline)
    flow_values, _flow_reason = _public_profile_learning_sequence(behavior_flow)
    return owner_canonical_behavior_flow_from_sources(
        raw_tags=raw_tag_values,
        ordered_events=ordered_event_values,
        behavior_timeline=timeline_values,
        behavior_flow=flow_values,
    )


def _learning_verdict_evidence(clean: bool, *, ready: bool, reason: str | None) -> Mapping[str, object]:
    degraded = reason is not None
    return _immutable_profile_learning_value({
        "clean": clean,
        "ready": ready,
        "degraded": degraded,
        "unavailable_reason": reason,
        "evidence_type": "profile_learning_verdict",
        "final_json_must_record": degraded,
        "replay_record_required": True,
    })


def learning_verdict_is_clean_evidence(verdict: object) -> Mapping[str, object]:
    """Evaluate the clean-verdict predicate and expose evidence."""
    try:
        result = owner_learning_verdict_is_clean(verdict)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return _learning_verdict_evidence(
            False,
            ready=False,
            reason="profile_learning_verdict_public_call_failed",
        )
    if type(result) is not bool:
        return _learning_verdict_evidence(
            False,
            ready=False,
            reason="profile_learning_verdict_result_invalid",
        )
    return _learning_verdict_evidence(result, ready=True, reason=None)


def learning_verdict_is_clean(verdict: object) -> bool:
    """Evaluate the canonical profile-learning clean-verdict predicate."""
    evidence = learning_verdict_is_clean_evidence(verdict)
    clean = evidence.get("clean", False)
    return clean is True


def commit_promoted_learning(
    engine: object,
    file_path: object,
    tags: object,
    *,
    yara_hits: object = None,
    risk: float = 0.0,
    strings_blob: str = "",
    verdict: object = None,
    api_calls: object = None,
    ordered_events: object = None,
    behavior_flow: object = None,
    prev_stage: object = "unknown",
    curr_stage: object = "unknown",
    observation_id: object = None,
    scan_integrity: object = None,
) -> object:
    """Commit clean profile learning through the canonical profile owner."""
    tag_values, tag_reason = (
        (tags, None)
        if type(tags) is TagEvidence
        else _public_profile_learning_sequence(tags)
    )
    yara_values, yara_reason = _public_profile_learning_sequence(yara_hits)
    api_values, api_reason = _public_profile_learning_sequence(api_calls)
    ordered_values, ordered_reason = _public_profile_learning_sequence(ordered_events)
    flow_values, flow_reason = _public_profile_learning_sequence(behavior_flow)
    malformed_reason = public_first_unavailable_reason(tag_reason, yara_reason, api_reason, ordered_reason, flow_reason)
    if malformed_reason:
        return _profile_learning_unavailable(malformed_reason)
    return _immutable_profile_learning_value(
        owner_commit_promoted_learning(
            engine,
            file_path,
            tag_values,
            yara_hits=yara_values,
            risk=risk,
            strings_blob=strings_blob,
            verdict=verdict,
            api_calls=api_values,
            ordered_events=ordered_values,
            behavior_flow=flow_values,
            prev_stage=prev_stage,
            curr_stage=curr_stage,
            observation_id=observation_id,
            scan_integrity=scan_integrity,
        )
    )


def behavior_vector_from_scan(
    engine: object,
    file_path: object,
    tags: object,
    *,
    risk: float = 0.0,
    strings_blob: str = "",
    api_calls: object = None,
    ordered_events: object = None,
) -> object:
    """Build a profile-owned behavior vector for replay learning."""
    tag_values, tag_reason = (
        (tags, None)
        if type(tags) is TagEvidence
        else _public_profile_learning_sequence(tags)
    )
    api_values, api_reason = _public_profile_learning_sequence(api_calls)
    ordered_values, ordered_reason = _public_profile_learning_sequence(ordered_events)
    malformed_reason = public_first_unavailable_reason(tag_reason, api_reason, ordered_reason)
    if malformed_reason:
        return _profile_learning_unavailable(malformed_reason, evidence_type="profile_behavior_vector")
    return _immutable_profile_learning_value(owner_behavior_vector_from_scan(
        engine,
        file_path,
        tag_values,
        api_calls=api_values,
        ordered_events=ordered_values,
    ))


__all__ = (
    "DEFAULT_ENGINES",
    "behavior_vector_from_scan",
    "canonical_behavior_flow_from_sources",
    "commit_promoted_learning",
    "learning_verdict_is_clean",
    "learning_verdict_is_clean_evidence",
)
