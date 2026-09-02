"""Immutable clustering feature semantics owned by the clustering model."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Final

CLUSTER_FEATURE_SCHEMA_VERSION: Final[str] = "cluster_feature_schema_v3"
ASSIGNMENT_SAFE: Final[str] = "assignment_safe"
EXPLANATION_ONLY: Final[str] = "explanation_only"
FEEDBACK_DERIVED: Final[str] = "feedback_derived"


@dataclass(frozen=True, slots=True)
class ClusterFeatureSpec:
    feature_id: str
    index: int
    semantic_type: str
    expected_min: float
    expected_max: float
    transform_id: str
    missing_policy: str
    provenance_family: str
    role: str
    schema_version: str = CLUSTER_FEATURE_SCHEMA_VERSION


CLUSTER_FEATURE_REGISTRY: Final[tuple[ClusterFeatureSpec, ...]] = (
    ClusterFeatureSpec("tag_count", 0, "count", 0.0, 10000.0, "log1p_robust_tanh", "unavailable", "tag_observation", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("tag_entropy", 1, "bounded_entropy", 0.0, 8.0, "bounded_unit", "unavailable", "tag_observation", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("unique_tag_count", 2, "count", 0.0, 10000.0, "log1p_robust_tanh", "unavailable", "tag_observation", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("graph_risk", 3, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "graph_model", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("graph_anomaly", 4, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "graph_model", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("temporal_belief", 5, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "temporal_model", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("markov_transition", 6, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "markov_model", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("markov_rarity", 7, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "markov_model", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("markov_pair_anomaly", 8, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "markov_model", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("unity_context", 9, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "engine_context", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("renpy_context", 10, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "engine_context", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("rpgm_context", 11, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "engine_context", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("media_context", 12, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "engine_context", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("other_context", 13, "unit_interval", 0.0, 1.0, "bounded_unit", "unavailable", "engine_context", ASSIGNMENT_SAFE),
    ClusterFeatureSpec("cluster_size", 14, "feedback", 0.0, 1.0, "none", "zero", "cluster_feedback", FEEDBACK_DERIVED),
    ClusterFeatureSpec("cluster_risk", 15, "feedback", 0.0, 1.0, "none", "zero", "cluster_feedback", FEEDBACK_DERIVED),
    ClusterFeatureSpec("cluster_anomaly", 16, "feedback", 0.0, 1.0, "none", "zero", "cluster_feedback", FEEDBACK_DERIVED),
)

VECTOR_FEATURE_NAMES: Final[tuple[str, ...]] = tuple(spec.feature_id for spec in CLUSTER_FEATURE_REGISTRY)
ASSIGNMENT_FEATURE_SPECS: Final[tuple[ClusterFeatureSpec, ...]] = tuple(
    spec for spec in CLUSTER_FEATURE_REGISTRY if spec.role == ASSIGNMENT_SAFE
)
ASSIGNMENT_FEATURE_NAMES: Final[tuple[str, ...]] = tuple(spec.feature_id for spec in ASSIGNMENT_FEATURE_SPECS)
ASSIGNMENT_FEATURE_INDICES: Final[tuple[int, ...]] = tuple(spec.index for spec in ASSIGNMENT_FEATURE_SPECS)
RAW_FEATURE_COUNT: Final[int] = len(CLUSTER_FEATURE_REGISTRY)
ASSIGNMENT_FEATURE_COUNT: Final[int] = len(ASSIGNMENT_FEATURE_SPECS)
EXPLANATION_FEATURE_NAMES: Final[tuple[str, ...]] = tuple(
    spec.feature_id for spec in CLUSTER_FEATURE_REGISTRY if spec.role != ASSIGNMENT_SAFE
)


def _registry_payload() -> list[dict[str, object]]:
    return [
        {
            "feature_id": spec.feature_id,
            "index": spec.index,
            "semantic_type": spec.semantic_type,
            "expected_min": spec.expected_min,
            "expected_max": spec.expected_max,
            "transform_id": spec.transform_id,
            "missing_policy": spec.missing_policy,
            "provenance_family": spec.provenance_family,
            "role": spec.role,
            "schema_version": spec.schema_version,
        }
        for spec in CLUSTER_FEATURE_REGISTRY
    ]


CLUSTER_FEATURE_REGISTRY_DIGEST: Final[str] = hashlib.sha256(
    json.dumps(_registry_payload(), sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
).hexdigest()


__all__ = (
    "ASSIGNMENT_FEATURE_INDICES",
    "ASSIGNMENT_FEATURE_COUNT",
    "ASSIGNMENT_FEATURE_NAMES",
    "ASSIGNMENT_FEATURE_SPECS",
    "ASSIGNMENT_SAFE",
    "CLUSTER_FEATURE_REGISTRY",
    "CLUSTER_FEATURE_REGISTRY_DIGEST",
    "CLUSTER_FEATURE_SCHEMA_VERSION",
    "ClusterFeatureSpec",
    "EXPLANATION_FEATURE_NAMES",
    "EXPLANATION_ONLY",
    "FEEDBACK_DERIVED",
    "RAW_FEATURE_COUNT",
    "VECTOR_FEATURE_NAMES",
)
