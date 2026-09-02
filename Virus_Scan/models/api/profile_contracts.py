"""Public profile-model read contracts for non-model consumers.

Profile model implementation modules own schema validation, default profile
construction, persisted profile loading, and learned extension baseline reads.
Callers outside ``Virus_Scan.models`` use this bounded API instead of importing
``Virus_Scan.models.profiles.api`` implementation internals directly.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.models.api.text_boundary import (
    public_api_contract_text,
    public_blank_mapping_key_label,
    public_duplicate_mapping_key_label,
    public_unavailable_contract_mapping,
    public_unreadable_mapping_key_label,
    public_unreadable_value_label,
)
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.models.profiles.baseline import get_extension_baseline as owner_get_extension_baseline
from Virus_Scan.models.profiles.persistence import load_engine_profile as owner_load_engine_profile
from Virus_Scan.models.profiles.quarantine import (
    profile_corruption_events_snapshot as owner_profile_corruption_events_snapshot,
)
from Virus_Scan.models.profiles.schema import (
    ProfileSchemaInvariantError,
    validate_engine_profile_schema as owner_validate_engine_profile_schema,
)
from Virus_Scan.models.profiles.snapshots import default_engine_profile as owner_default_engine_profile


def _detached_profile_contract_text(value: object) -> str:
    """Return exact built-in public profile text without caller hooks."""
    text, _reason = public_api_contract_text(
        value,
        default_text=public_unreadable_value_label(value),
    )
    return text


def _profile_text_default_text(default_text: object, default: str) -> str:
    if default_text is None:
        return default
    try:
        text = _detached_profile_contract_text(default_text)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return default
    if text == "":
        return default
    return text


def _safe_public_profile_text(value: object, *, default_text: str | None = None) -> str:
    default = default_text if default_text is not None else public_unreadable_value_label(value)
    text, reason = public_api_contract_text(value, default_text=default)
    if reason is not None:
        return text
    if text == "":
        return _profile_text_default_text(default_text, "<blank>")
    return text


def _immutable_profile_value(value: object) -> object:
    """Return a deterministic immutable public-profile contract value.

    Only exact builtin containers and owned immutable mapping proxies are
    traversed. Unknown mapping/iterable objects are represented as explicit
    unavailable evidence so public profile snapshots cannot invoke caller-owned
    mapping, iteration, string, repr, numeric, or property hooks.
    """
    items = no_hook_mapping_items(value)
    if items is not None:
        out = {}
        keyed: list[tuple[str, int, object]] = []
        for index, (key, child) in enumerate(items):
            key_text = _safe_public_profile_text(key, default_text=public_unreadable_mapping_key_label(index))
            if key_text == "":
                key_text = public_blank_mapping_key_label(index)
            keyed.append((key_text, index, child))
        for raw_key_text, index, child in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in out:
                key_text = public_duplicate_mapping_key_label(key_text, index)
            out[key_text] = _immutable_profile_value(child)
        return MappingProxyType(out)
    if isinstance(value, Mapping):
        return public_unavailable_contract_mapping(
            "unreadable_public_mapping_items",
            evidence_type="profile_public_contract_value_unavailable",
        )
    if type(value) in (list, tuple):
        return tuple(_immutable_profile_value(item) for item in value)
    if type(value) in (set, frozenset):
        ordered = sorted(
            value,
            key=lambda item: no_hook_json_sort_key(_immutable_profile_value(item)),
        )
        return tuple(_immutable_profile_value(item) for item in ordered)
    if isinstance(value, str):
        return str.__str__(_safe_public_profile_text(value))
    if type(value) is bool or type(value) is int or type(value) is float or value is None:
        return value
    return public_unavailable_contract_mapping(
        "unreadable_public_contract_text",
        evidence_type="profile_public_contract_value_unavailable",
    )


def _safe_profile_text(value: object, default: str = "other") -> str:
    source = default if value is None else value
    default_text = "<" + no_hook_type_name(value) + ">" if value is not None else default
    text, reason = public_api_contract_text(source, default_text=default_text)
    if reason is not None:
        return default_text
    if text == "":
        return default
    return text


def default_engine_profile(engine: str) -> Mapping[str, object]:
    """Return the canonical model-owned default engine profile."""
    return _immutable_profile_value(owner_default_engine_profile(_safe_profile_text(engine)))


def load_engine_profile(engine: str) -> Mapping[str, object]:
    """Load the canonical model-owned engine profile."""
    return _immutable_profile_value(owner_load_engine_profile(_safe_profile_text(engine)))


def get_temporal_baselines(engine: str) -> Mapping[str, object]:
    """Return the profile-owned canonical v5 temporal baseline store."""
    try:
        profile = owner_load_engine_profile(_safe_profile_text(engine))
        if type(profile) is not dict:
            raise ValueError("profile temporal baseline owner invalid")
        model_state = dict.get(profile, "model_state")
        if type(model_state) is not dict:
            raise ValueError("profile temporal model state invalid")
        baselines = dict.get(model_state, "temporal_baselines")
        if type(baselines) is not dict:
            raise ValueError("profile temporal baselines invalid")
        return _immutable_profile_value(baselines)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return _immutable_profile_value({
            "ready": False,
            "degraded": True,
            "unavailable_reason": "profile_temporal_baselines_unavailable",
            "evidence_type": "profile_temporal_baselines",
            "final_json_must_record": True,
            "replay_record_required": True,
        })


def get_extension_baseline(
    engine: str,
    file_path: object,
    *,
    evidence_context: object | None = None,
    router_identity: object | None = None,
) -> Mapping[str, object]:
    """Read the canonical learned extension baseline for a file context."""
    try:
        return _immutable_profile_value(
            owner_get_extension_baseline(
                _safe_profile_text(engine),
                file_path,
                evidence_context=evidence_context,
                router_identity=router_identity,
            )
        )
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return _immutable_profile_value({
            "ready": False,
            "degraded": True,
            "unavailable_reason": "extension_baseline_public_input_invalid",
            "evidence_type": "profile_extension_baseline",
            "final_json_must_record": True,
            "replay_record_required": True,
        })


def _profile_schema_validation_evidence(valid: bool, *, ready: bool, reason: str | None) -> Mapping[str, object]:
    degraded = reason is not None
    return _immutable_profile_value({
        "valid": valid,
        "ready": ready,
        "degraded": degraded,
        "unavailable_reason": reason,
        "evidence_type": "profile_schema_validation",
        "final_json_must_record": degraded,
        "replay_record_required": True,
    })


def validate_engine_profile_schema_evidence(profile: Mapping[str, object], *, expected_engine: str) -> Mapping[str, object]:
    """Validate a profile and expose explicit public-contract evidence."""
    if no_hook_mapping_items(profile) is None:
        return _profile_schema_validation_evidence(
            False,
            ready=False,
            reason="profile_schema_public_input_not_mapping",
        )
    try:
        result = owner_validate_engine_profile_schema(profile, expected_engine=_safe_profile_text(expected_engine))
    except ProfileSchemaInvariantError:
        raise
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return _profile_schema_validation_evidence(
            False,
            ready=False,
            reason="profile_schema_validation_failed",
        )
    if type(result) is not bool:
        return _profile_schema_validation_evidence(
            False,
            ready=False,
            reason="profile_schema_validation_result_invalid",
        )
    return _profile_schema_validation_evidence(result, ready=True, reason=None)


def validate_engine_profile_schema(profile: Mapping[str, object], *, expected_engine: str) -> bool:
    """Validate a profile through the canonical profile schema owner."""
    evidence = validate_engine_profile_schema_evidence(profile, expected_engine=expected_engine)
    valid = evidence.get("valid", False)
    return valid is True


def profile_corruption_events_snapshot() -> tuple[object, ...]:
    """Return immutable profile-corruption evidence recorded by the profile owner."""
    events = owner_profile_corruption_events_snapshot()
    immutable = _immutable_profile_value(events)
    if isinstance(immutable, tuple):
        return immutable
    if immutable is None:
        return ()
    try:
        return tuple(immutable)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return (
            public_unavailable_contract_mapping(
                "profile_corruption_events_unreadable",
                evidence_type="profile_public_contract_value_unavailable",
            ),
        )


__all__ = (
    "ProfileSchemaInvariantError",
    "default_engine_profile",
    "get_extension_baseline",
    "get_temporal_baselines",
    "load_engine_profile",
    "profile_corruption_events_snapshot",
    "validate_engine_profile_schema",
    "validate_engine_profile_schema_evidence",
)
