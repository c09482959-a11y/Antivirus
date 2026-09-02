"""Explicit runtime-owned clustering state binding.

The clustering model computes cluster membership and feature vectors, but the
mutable storage object must be owned by the runtime lifecycle, not by a module
singleton.  This module only defines the state type and a context binding.  The
binding is installed by bootstrap/runtime construction and raises if clustering
is used before ownership is explicit.
"""
from __future__ import annotations

from collections import defaultdict
import math
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import RLock
from typing import NoReturn

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_text,
    no_hook_type_name,
    no_hook_mapping_items,
)


CLUSTER_STATE_SCHEMA_VERSION = "online_microcluster_state_v2"
CLUSTER_STATE_MAX_CLUSTERS = 2000
CLUSTER_STATE_MAX_NODE_ASSIGNMENTS = 50000
CLUSTER_STATE_MAX_LEARNING_KEYS = 4096


class ClusterStateNotConfigured(RuntimeError):
    """Raised when clustering state is requested before runtime ownership is bound."""


_RUNTIME_CLUSTER_STATE_TYPE_REQUIRED = "runtime cluster state must be RuntimeClusterState"


def _raise_runtime_cluster_state_type_required() -> NoReturn:
    raise TypeError(_RUNTIME_CLUSTER_STATE_TYPE_REQUIRED)


@dataclass
class RuntimeClusterState:
    node_cluster_map: dict[str, str] = field(default_factory=dict)
    malicious_clusters: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    benign_clusters: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    mixed_clusters: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    cluster_metadata: dict[str, object] = field(default_factory=dict)
    cluster_signatures: dict[str, list[float]] = field(default_factory=dict)
    node_feature_vectors: dict[str, list[float]] = field(default_factory=dict)
    cluster_tag_signatures: dict[str, set[str]] = field(default_factory=dict)
    applied_learning_keys: dict[str, int] = field(default_factory=dict)
    lock: RLock = field(default_factory=RLock)


_CLUSTER_STATE_BINDING: ContextVar[RuntimeClusterState | None] = ContextVar(
    'umige_runtime_cluster_state',
    default=None,
)


def configure_runtime_cluster_state(state: RuntimeClusterState) -> None:
    """Bind the clustering state object owned by the current runtime context."""
    if type(state) is not RuntimeClusterState:
        _raise_runtime_cluster_state_type_required()
    _CLUSTER_STATE_BINDING.set(state)


def cluster_state() -> RuntimeClusterState:
    """Return the explicitly bound clustering state for this runtime context."""
    state = _CLUSTER_STATE_BINDING.get()
    if state is None:
        exception_message = 'runtime cluster state not configured'
        raise ClusterStateNotConfigured(exception_message)
    return state



_CLUSTER_TEXT_UNAVAILABLE = "cluster_state_text_unavailable"
_CLUSTER_VALUE_UNAVAILABLE = "cluster_state_value_unavailable"


def _cluster_owned_text(*parts: str) -> str:
    return "".join(parts)


def _cluster_text_unavailable(value: object) -> str:
    return _cluster_owned_text(_CLUSTER_TEXT_UNAVAILABLE, ":", no_hook_type_name(value))


def _cluster_field_reason(prefix: str, field_name: str, suffix: str) -> str:
    return _cluster_owned_text(prefix, field_name, suffix)


def _cluster_metadata_evidence_key(name: str, suffix: str) -> str:
    return _cluster_owned_text(name, suffix)


def _cluster_state_exact_text(value: object, default_text: str = "") -> str:
    """Detach runtime cluster snapshot text without caller-owned truthiness/str hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_cluster_state_text",
        unsupported_reason="unsafe_cluster_state_text_rejected",
    )
    text = str.strip(text) if type(text) is str else ""
    if reason == "" and text != "":
        return text
    if default_text != "":
        return default_text
    if value is None:
        return ""
    return _cluster_text_unavailable(value)


def _cluster_state_sort_key(value: object) -> tuple[str, str]:
    return (_cluster_state_exact_text(value), no_hook_type_name(value))


def _cluster_float_result(
    value: object,
    *,
    field_name: str,
    default: float = 0.0,
) -> tuple[float, str]:
    """Return a finite scalar plus explicit evidence for rejected values."""
    number, reason = no_hook_finite_float(
        value,
        default=default,
        reason=_cluster_field_reason("unsafe_", field_name, "_rejected"),
        non_finite_reason=_cluster_field_reason("nonfinite_", field_name, ""),
        allow_exact_text=False,
    )
    return number, reason


def _finite_cluster_float(value: object, default: float = 0.0) -> float:
    """Return a finite cluster-model scalar without caller-owned numeric hooks."""
    number, _reason = _cluster_float_result(
        value,
        field_name="cluster_numeric_value",
        default=default,
    )
    return number


def _cluster_unavailable_value(value: object, reason: str = "unsafe_cluster_metadata_value_rejected") -> str:
    return _cluster_owned_text(_CLUSTER_VALUE_UNAVAILABLE, ":", reason, ":", no_hook_type_name(value))


def _cluster_metadata_reason(value: object) -> str:
    if type(value) is float and not math.isfinite(value):
        return "nonfinite_cluster_numeric_value"
    if type(value) in (str, bytes, bytearray, bool, int, float, set, frozenset, list, tuple, dict) or value is None:
        return ""
    _sequence_items, sequence_reason = _cluster_sequence_items(value)
    _mapping_items, mapping_reason = _cluster_mapping_items(value)
    if sequence_reason == "" or mapping_reason == "":
        return ""
    return "unsafe_cluster_metadata_value_rejected"


def _cluster_sequence_items(values: object) -> tuple[tuple[object, ...], str]:
    if type(values) is tuple:
        return values, ""
    if type(values) is list:
        return tuple(values), ""
    if isinstance(values, list) and type(values).__iter__ is list.__iter__:
        return tuple(list.__iter__(values)), ""
    if isinstance(values, tuple) and type(values).__iter__ is tuple.__iter__:
        return tuple(tuple.__iter__(values)), ""
    return (), "cluster_sequence_unsupported"


def _cluster_mapping_items(value: object) -> tuple[tuple[tuple[object, object], ...], str]:
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return (), "cluster_mapping_unsupported"
    return items, ""


def _cluster_mapping_lookup(value: object, key: str) -> tuple[bool, object]:
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return False, None
    for candidate, item in items:
        if type(candidate) is str and candidate == key:
            return True, item
    return False, None


def _sanitize_cluster_vector(
    values: object,
    *,
    field_name: str,
) -> tuple[list[float], list[dict[str, object]]]:
    items, item_reason = _cluster_sequence_items(values)
    if item_reason:
        return [], [
            {
                "field_name": field_name,
                "reason": _cluster_field_reason("", field_name, "_sequence_rejected"),
                "value_type": no_hook_type_name(values),
            }
        ]
    vector: list[float] = []
    evidence: list[dict[str, object]] = []
    for index, item in enumerate(items[:256]):
        number, reason = _cluster_float_result(
            item,
            field_name=_cluster_field_reason("", field_name, "_member"),
        )
        vector.append(number)
        if reason:
            evidence.append(
                {
                    "field_name": field_name,
                    "index": index,
                    "reason": reason,
                    "value_type": no_hook_type_name(item),
                }
            )
    return vector, evidence


def _cluster_rank_values(meta: object) -> tuple[tuple[float, int, float], dict[str, object]]:
    evidence: dict[str, object] = {}
    values: dict[str, float] = {}
    for field_name in ("confidence", "malicious_ratio", "last_updated"):
        found, raw_value = _cluster_mapping_lookup(meta, field_name)
        if not found:
            values[field_name] = 0.0
            continue
        parsed, reason = _cluster_float_result(raw_value, field_name=field_name)
        values[field_name] = parsed
        if reason:
            evidence[_cluster_metadata_evidence_key(field_name, "_unavailable_reason")] = reason
            evidence[_cluster_metadata_evidence_key(field_name, "_value_type")] = no_hook_type_name(raw_value)

    found_samples, raw_samples = _cluster_mapping_lookup(meta, "samples")
    samples = 0
    if found_samples:
        samples, reason = no_hook_exact_nonnegative_int(
            raw_samples,
            default=0,
            reason="unsafe_cluster_samples_rejected",
            non_finite_reason="nonfinite_cluster_samples",
            allow_exact_text=False,
        )
        if reason:
            evidence["samples_unavailable_reason"] = reason
            evidence["samples_value_type"] = no_hook_type_name(raw_samples)

    rank = (
        max(0.0, min(1.0, values["confidence"]))
        + max(0.0, min(1.0, values["malicious_ratio"])),
        samples,
        values["last_updated"],
    )
    return rank, evidence


def _json_safe_cluster_value(value: object, *, key_name: str = "") -> object:
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        return _finite_cluster_float(value, 0.0)
    if type(value) is str:
        return value
    if isinstance(value, str) or type(value) in (bytes, bytearray):
        return _cluster_state_exact_text(value)
    if type(value) in (set, frozenset):
        limit = 2048 if key_name == "members" else 250
        return sorted((_cluster_state_exact_text(item) for item in value), key=lambda item: item)[:limit]
    items, item_reason = _cluster_sequence_items(value)
    if not item_reason:
        if key_name == "centroid_vector":
            return _sanitize_cluster_vector(
                items,
                field_name="centroid_vector",
            )[0]
        limit = 2048 if key_name == "members" else 512
        return [_json_safe_cluster_value(item) for item in items[:limit]]
    mapping_items, mapping_reason = _cluster_mapping_items(value)
    if not mapping_reason:
        out: dict[str, object] = {}
        for key, item in sorted(mapping_items, key=lambda row: _cluster_state_sort_key(row[0]))[:250]:
            name = _cluster_state_exact_text(key)
            if name == "":
                name = _cluster_text_unavailable(key)
            out[name] = _json_safe_cluster_value(item, key_name=name)
        return out
    return _cluster_unavailable_value(value)


def _json_safe_cluster_meta(meta: object) -> dict[str, object]:
    mapping_items, mapping_reason = _cluster_mapping_items(meta)
    if mapping_reason:
        return {
            "metadata_unavailable_reason": "non_materializable_cluster_metadata",
            "metadata_value_type": no_hook_type_name(meta),
        }
    # Runtime cluster snapshots are replay-compared as model evidence.  Truncating
    # caller-owned metadata in insertion order lets equivalent metadata retain
    # different keys depending on construction/replay order, so all mapping keys
    # are canonicalized before limits are applied.
    out: dict[str, object] = {}
    for key, value in sorted(mapping_items, key=lambda item: _cluster_state_sort_key(item[0]))[:250]:
        name = _cluster_state_exact_text(key)
        if name == "":
            name = _cluster_text_unavailable(key)
        out[name] = _json_safe_cluster_value(value, key_name=name)
        if name == "centroid_vector":
            _vector, vector_evidence = _sanitize_cluster_vector(
                value,
                field_name="centroid_vector",
            )
            if vector_evidence:
                out["centroid_vector_unavailable_reasons"] = vector_evidence
        reason = _cluster_metadata_reason(value)
        if reason:
            out[_cluster_metadata_evidence_key(name, "_unavailable_reason")] = reason
            out[_cluster_metadata_evidence_key(name, "_value_type")] = no_hook_type_name(value)
    return out

def runtime_cluster_state_to_json() -> dict[str, object]:
    """Serialize the single canonical v2 microcluster schema and owned indexes."""
    state = cluster_state()
    ranked: list[tuple[tuple[float, int, float], str, dict[str, object]]] = []
    with state.lock:
        metadata_items, _metadata_reason = _cluster_mapping_items(state.cluster_metadata)
        for raw_cluster_id, meta in metadata_items:
            cluster_id = _cluster_state_exact_text(raw_cluster_id)
            if cluster_id == "":
                continue
            rank, rank_evidence = _cluster_rank_values(meta)
            serialized = _json_safe_cluster_meta(meta)
            for name, value in rank_evidence.items():
                serialized.setdefault(name, value)
            ranked.append((rank, cluster_id, serialized))
        ranked.sort(key=lambda row: (row[0], row[1]), reverse=True)
        retained = ranked[:CLUSTER_STATE_MAX_CLUSTERS]
        retained_ids = {cluster_id for _rank, cluster_id, _meta in retained}
        node_map: dict[str, str] = {}
        for raw_node, raw_cluster_id in sorted(
            tuple(state.node_cluster_map.items()),
            key=lambda row: _cluster_state_sort_key(row[0]),
        )[:CLUSTER_STATE_MAX_NODE_ASSIGNMENTS]:
            node = _cluster_state_exact_text(raw_node)
            cluster_id = _cluster_state_exact_text(raw_cluster_id)
            if node and cluster_id in retained_ids:
                node_map[node] = cluster_id
        node_vectors: dict[str, list[float]] = {}
        for node in sorted(node_map):
            if node in state.node_feature_vectors:
                vector, evidence = _sanitize_cluster_vector(
                    state.node_feature_vectors[node], field_name="node_feature_vector",
                )
                node_vectors[node] = [] if evidence else vector
        applied = {
            _cluster_state_exact_text(key): ordinal
            for ordinal, key in sorted(
                (
                    value if type(value) is int and value >= 0 else 0,
                    _cluster_state_exact_text(key),
                )
                for key, value in state.applied_learning_keys.items()
            )[-CLUSTER_STATE_MAX_LEARNING_KEYS:]
            if key
        }
    return {
        "schema": CLUSTER_STATE_SCHEMA_VERSION,
        "microclusters": {
            cluster_id: meta for _rank, cluster_id, meta in retained
        },
        "node_cluster_map": node_map,
        "node_feature_vectors": node_vectors,
        "applied_learning_keys": applied,
    }


__all__ = (
    'CLUSTER_STATE_SCHEMA_VERSION',
    'CLUSTER_STATE_MAX_CLUSTERS',
    'CLUSTER_STATE_MAX_LEARNING_KEYS',
    'CLUSTER_STATE_MAX_NODE_ASSIGNMENTS',
    'ClusterStateNotConfigured',
    'RuntimeClusterState',
    'cluster_state',
    'configure_runtime_cluster_state',
    'runtime_cluster_state_to_json',
)
