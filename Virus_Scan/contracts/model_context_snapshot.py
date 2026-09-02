"""Canonical immutable model/context snapshot with zero evidence authority."""
from __future__ import annotations

from dataclasses import dataclass, field
from math import isfinite
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.model_projection_identity import require_model_projection_identity
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items

MODEL_CONTEXT_SNAPSHOT_SCHEMA_VERSION = "stage2636_11020_model_context_snapshot_v2"
_MAX_ITEMS = 4096
_HEX = frozenset("0123456789abcdef")


def _digest(value: object, reason: str, *, allow_blank: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value).strip().lower()
    if allow_blank and text == "":
        return ""
    if len(text) != 64 or any(character not in _HEX for character in text):
        raise ValueError(reason)
    return text


def _sort_key(value: object) -> str:
    return canonical_json_sha256(_plain(value))


def _freeze(value: object, *, depth: int = 0) -> object:
    if depth > 32:
        raise ValueError("model_context_value_depth_exceeded")
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is float:
        if not isfinite(value):
            raise ValueError("model_context_nonfinite_value")
        return value
    items = no_hook_mapping_items(value)
    if items is not None:
        if len(items) > _MAX_ITEMS:
            raise ValueError("model_context_mapping_too_large")
        frozen: dict[str, object] = {}
        for key, item in items:
            if type(key) is not str or not key or len(key) > 256:
                raise TypeError("model_context_mapping_key_invalid")
            if key in frozen:
                raise ValueError("model_context_mapping_key_duplicate")
            frozen[str.__str__(key)] = _freeze(item, depth=depth + 1)
        return MappingProxyType(dict(sorted(frozen.items())))
    if type(value) in (tuple, list, set, frozenset):
        sequence = tuple(value)
        if len(sequence) > _MAX_ITEMS:
            raise ValueError("model_context_sequence_too_large")
        frozen_items = tuple(_freeze(item, depth=depth + 1) for item in sequence)
        if type(value) in (set, frozenset):
            frozen_items = tuple(sorted(frozen_items, key=_sort_key))
        return frozen_items
    if hasattr(value, 'to_record') and callable(value.to_record):
        return _freeze(value.to_record(), depth=depth + 1)
    raise TypeError("model_context_value_type_invalid")


def _plain(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        return {str.__str__(key): _plain(item) for key, item in items}
    if type(value) is tuple:
        return tuple(_plain(item) for item in value)
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise TypeError("model_context_frozen_value_invalid")


def _mapping(value: object, reason: str) -> Mapping[str, object]:
    frozen = _freeze(value)
    if type(frozen) is not type(MappingProxyType({})):
        raise TypeError(reason)
    return frozen


def _sequence(value: object, reason: str) -> tuple[object, ...]:
    frozen = _freeze(value)
    if type(frozen) is not tuple:
        raise TypeError(reason)
    return frozen


@dataclass(frozen=True, slots=True)
class ModelContextSnapshot:
    """Context-only model projections for one artifact-evidence generation.

    The evidence link is the immutable source-evidence digest.  Projection
    identity binds the exact scan/model/registry generation that produced the
    context.  The contract contains no TagEvidence, ChainEvidence, physical
    root, or technique decision field and therefore cannot satisfy evidence.
    """

    source_artifact_evidence_digest: str
    projection_identity: Mapping[str, object]
    graph_features: Mapping[str, object] = field(default_factory=dict)
    temporal_features: Mapping[str, object] = field(default_factory=dict)
    markov_features: Mapping[str, object] = field(default_factory=dict)
    engine_context: Mapping[str, object] = field(default_factory=dict)
    profile_context: Mapping[str, object] = field(default_factory=dict)
    behavior_flow: tuple[object, ...] = ()
    feature_vector: tuple[object, ...] = ()
    cluster_context: Mapping[str, object] = field(default_factory=dict)
    attack_family_classifier_context: Mapping[str, object] = field(default_factory=dict)
    failure_evidence: tuple[object, ...] = ()
    semantic_digest: str = ""
    schema_version: str = MODEL_CONTEXT_SNAPSHOT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ModelContextSnapshot:
            raise TypeError("model_context_snapshot_owner_invalid")
        source_digest = _digest(
            self.source_artifact_evidence_digest,
            "model_context_source_evidence_digest_invalid",
        )
        projection_identity = require_model_projection_identity(self.projection_identity)
        values = {
            "graph_features": _mapping(self.graph_features, "model_context_graph_features_invalid"),
            "temporal_features": _mapping(self.temporal_features, "model_context_temporal_features_invalid"),
            "markov_features": _mapping(self.markov_features, "model_context_markov_features_invalid"),
            "engine_context": _mapping(self.engine_context, "model_context_engine_context_invalid"),
            "profile_context": _mapping(self.profile_context, "model_context_profile_context_invalid"),
            "behavior_flow": _sequence(self.behavior_flow, "model_context_behavior_flow_invalid"),
            "feature_vector": _sequence(self.feature_vector, "model_context_feature_vector_invalid"),
            "cluster_context": _mapping(self.cluster_context, "model_context_cluster_context_invalid"),
            "attack_family_classifier_context": _mapping(
                self.attack_family_classifier_context,
                "model_context_attack_family_classifier_invalid",
            ),
            "failure_evidence": _sequence(self.failure_evidence, "model_context_failure_evidence_invalid"),
        }
        if self.schema_version != MODEL_CONTEXT_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("model_context_snapshot_schema_invalid")
        object.__setattr__(self, "source_artifact_evidence_digest", source_digest)
        object.__setattr__(self, "projection_identity", projection_identity)
        for name, value in values.items():
            object.__setattr__(self, name, value)
        computed = canonical_json_sha256(self._semantic_record())
        supplied = _digest(
            self.semantic_digest,
            "model_context_semantic_digest_invalid",
            allow_blank=True,
        )
        if supplied not in ("", computed):
            raise ValueError("model_context_semantic_digest_mismatch")
        object.__setattr__(self, "semantic_digest", computed)

    def _semantic_record(self) -> dict[str, object]:
        return {
            "attack_family_classifier_context": _plain(self.attack_family_classifier_context),
            "behavior_flow": _plain(self.behavior_flow),
            "cluster_context": _plain(self.cluster_context),
            "engine_context": _plain(self.engine_context),
            "failure_evidence": _plain(self.failure_evidence),
            "feature_vector": _plain(self.feature_vector),
            "graph_features": _plain(self.graph_features),
            "markov_features": _plain(self.markov_features),
            "profile_context": _plain(self.profile_context),
            "projection_identity": _plain(self.projection_identity),
            "schema_version": self.schema_version,
            "source_artifact_evidence_digest": self.source_artifact_evidence_digest,
            "temporal_features": _plain(self.temporal_features),
        }

    def to_record(self) -> dict[str, object]:
        record = self._semantic_record()
        record["semantic_digest"] = self.semantic_digest
        record["evidence_authority"] = "context_only"
        record["official_decision_effect"] = "none"
        return record


__all__ = (
    "MODEL_CONTEXT_SNAPSHOT_SCHEMA_VERSION",
    "ModelContextSnapshot",
)
