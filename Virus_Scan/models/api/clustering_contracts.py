"""Public clustering model contract.

Orchestration may decide *when* persisted model state is hydrated, but the
clustering model owns how cluster snapshots are interpreted and applied to
runtime cluster state.  This public model API keeps non-model callers away from
``Virus_Scan.models.clustering`` implementation internals while preserving the
canonical clustering owner.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from Virus_Scan.runtime.cluster_state import ClusterStateNotConfigured
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence

from Virus_Scan.models.api.text_boundary import (
    public_api_contract_text,
    public_duplicate_mapping_key_label,
    public_first_unavailable_reason,
    public_unavailable_contract_mapping,
    public_unreadable_mapping_key_label,
    public_unreadable_value_label,
)

from Virus_Scan.models.contracts.learning_authority import learning_authorization_failure

from Virus_Scan.models.clustering.assignment import (
    assign_cluster_with_context_tags as owner_assign_cluster_with_context_tags,
)
from Virus_Scan.models.clustering.common import (
    VECTOR_FEATURE_NAMES as owner_VECTOR_FEATURE_NAMES,
)
from Virus_Scan.models.clustering.snapshots import (
    load_runtime_model_record as owner_load_runtime_model_record,
)
from Virus_Scan.models.clustering.vector_baseline import online_vector_update as owner_online_vector_update
from Virus_Scan.models.clustering.learning_features import build_learning_feature_vector as owner_build_learning_feature_vector


VECTOR_FEATURE_NAMES = tuple(owner_VECTOR_FEATURE_NAMES)

_MAPPING_PROXY_TYPE: type = type(MappingProxyType({}))



def _detached_cluster_contract_text(value: object) -> str:
    """Return exact built-in public cluster text without caller hooks."""
    text, _reason = public_api_contract_text(
        value,
        default_text=public_unreadable_value_label(value),
    )
    return text


def _cluster_text_default_text(default_text: object, default: str) -> str:
    if default_text is None:
        return default
    try:
        text = _detached_cluster_contract_text(default_text)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return default
    if text == "":
        return default
    return text


def _safe_public_cluster_text(value: object, *, default_text: str | None = None) -> str:
    default = default_text if default_text is not None else public_unreadable_value_label(value)
    text, reason = public_api_contract_text(value, default_text=default)
    if reason is not None:
        return text
    if text == "":
        return _cluster_text_default_text(default_text, "<blank>")
    return text


def _immutable_cluster_value(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        out = {}
        keyed = []
        for index, (key, child) in enumerate(items):
            key_text = _safe_public_cluster_text(key, default_text=public_unreadable_mapping_key_label(index))
            keyed.append((key_text, index, child))
        for raw_key_text, index, child in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in out:
                key_text = public_duplicate_mapping_key_label(key_text, index)
            out[key_text] = _immutable_cluster_value(child)
        return MappingProxyType(out)
    if isinstance(value, Mapping):
        return public_unavailable_contract_mapping(
            "unsupported_public_mapping",
            evidence_type="cluster_public_contract_value_unavailable",
        )
    if type(value) in (list, tuple):
        return tuple(_immutable_cluster_value(item) for item in value)
    if type(value) in (set, frozenset):
        ordered = sorted(value, key=lambda item: (_safe_public_cluster_text(no_hook_type_name(item)), _safe_public_cluster_text(item)))
        return tuple(_immutable_cluster_value(item) for item in ordered)
    if isinstance(value, str):
        return str.__str__(_safe_public_cluster_text(value))
    if type(value) in (int, float, bool) or value is None:
        return value
    _text, _reason = public_api_contract_text(value, default_text=public_unreadable_value_label(value))
    if _reason is not None:
        return public_unavailable_contract_mapping(
            "unreadable_public_contract_text",
            evidence_type="cluster_public_contract_value_unavailable",
        )
    return _text


def _public_cluster_sequence(value: object, *, allow_mapping: bool = False) -> tuple[tuple[object, ...], str | None]:
    if value is None:
        return (), None
    if isinstance(value, (str, bytes)):
        return (), "invalid_cluster_vector_sequence"
    items = no_hook_mapping_items(value)
    if items is not None:
        if allow_mapping:
            return items, None
        return (), "invalid_cluster_vector_sequence"
    if isinstance(value, Mapping):
        return (), "unsupported_cluster_vector_mapping"
    if type(value) in (tuple, list, set, frozenset):
        return tuple(value), None
    if isinstance(value, Iterable):
        return (), "unsupported_cluster_vector_iterable"
    return (), "invalid_cluster_vector_sequence"


def _public_mapping_snapshot(value: object, *, reason: str) -> tuple[dict[object, object], str | None]:
    if value is None:
        return {}, None
    items = no_hook_mapping_items(value)
    if items is None:
        if isinstance(value, Mapping):
            return {}, reason
        return {}, None
    return dict(items), None


def _public_tag_sequence(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    if no_hook_mapping_items(value) is not None:
        return (value,)
    if isinstance(value, Mapping):
        return ("cluster_public_tag_mapping_unavailable",)
    if type(value) in (tuple, list, set, frozenset):
        return tuple(value)
    if isinstance(value, Iterable):
        return ("cluster_public_tag_iterable_unavailable",)
    return (value,)


def _cluster_unavailable(reason: str) -> Mapping[str, object]:
    return _immutable_cluster_value({
        "assigned": False,
        "cluster_id": None,
        "updated": False,
        "ready": False,
        "degraded": True,
        "reason": reason,
        "unavailable_reason": reason,
        "cluster_unavailable_reason": reason,
        "evidence_type": "cluster_public_contract",
        "final_json_must_record": True,
        "replay_record_required": True,
    })


def assign_cluster_with_context_tags(
    node: object, feature_vector: object, *, tags: object = None,
    engine_context: object = None,
    learning_decision: object = None,
) -> object:
    """Assign a vector through the canonical clustering model owner."""
    authorization_reason = learning_authorization_failure(learning_decision, "clustering")
    if authorization_reason is not None:
        return _cluster_unavailable(authorization_reason)
    vector_values, vector_reason = _public_cluster_sequence(feature_vector)
    if vector_reason:
        return _cluster_unavailable(vector_reason)
    tag_input = tags if type(tags) is TagEvidence else tags
    try:
        result = owner_assign_cluster_with_context_tags(
            node,
            vector_values,
            tags=tag_input,
            engine_context=engine_context if isinstance(engine_context, Mapping) else None,
            learning_decision=learning_decision,
        )
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError, ClusterStateNotConfigured):
        return _cluster_unavailable("cluster_assignment_unavailable")
    return _immutable_cluster_value(result)



def build_learning_feature_vector(
    tags: object, engine_context: object,
) -> object:
    """Build clustering's raw-only authorized-learning projection."""
    tag_values = tags if type(tags) is TagEvidence else _public_cluster_sequence(tags)[0]
    context_items = no_hook_mapping_items(engine_context)
    context = dict(context_items) if context_items is not None else {}
    try:
        result = owner_build_learning_feature_vector(tag_values, context)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return _cluster_unavailable("cluster_learning_feature_projection_unavailable")
    return _immutable_cluster_value(result)

def online_vector_update(vector_baseline: object, vector: object, feature_names: object = None) -> object:
    """Update an extension vector baseline through the canonical clustering owner."""
    vector_values, vector_reason = _public_cluster_sequence(vector)
    if vector_reason:
        return _cluster_unavailable(vector_reason)
    feature_name_values, feature_reason = _public_cluster_sequence(feature_names)
    names = feature_name_values if feature_names is not None and not feature_reason else None
    baseline_values, baseline_reason = _public_mapping_snapshot(
        vector_baseline,
        reason="unreadable_cluster_baseline_mapping",
    )
    try:
        result = owner_online_vector_update(
            baseline_values,
            vector_values,
            names,
        )
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return _cluster_unavailable("cluster_vector_update_unavailable")
    unavailable_reason = public_first_unavailable_reason(baseline_reason, feature_reason)
    if unavailable_reason and isinstance(result, Mapping):
        out = dict(result)
        out["degraded"] = True
        out["unavailable_reason"] = unavailable_reason
        out["cluster_unavailable_reason"] = unavailable_reason
        out["final_json_must_record"] = True
        out["replay_record_required"] = True
        return _immutable_cluster_value(out)
    return _immutable_cluster_value(result)


def load_cluster_runtime_model_record(value: object) -> object:
    """Hydrate clustering from the canonical current-schema record."""
    try:
        return owner_load_runtime_model_record(value)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return _cluster_unavailable("cluster_runtime_model_state_load_failed")



__all__ = (
    "VECTOR_FEATURE_NAMES",
    "build_learning_feature_vector",
    "assign_cluster_with_context_tags",
    "load_cluster_runtime_model_record",
    "online_vector_update",
)
