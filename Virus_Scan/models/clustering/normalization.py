"""Versioned robust normalization for clustering assignment vectors."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Final

from Virus_Scan.models.clustering.common import cluster_input_sequence
from Virus_Scan.models.clustering.feature_registry import (
    ASSIGNMENT_FEATURE_COUNT,
    RAW_FEATURE_COUNT,
    ASSIGNMENT_FEATURE_SPECS,
    CLUSTER_FEATURE_REGISTRY,
    CLUSTER_FEATURE_SCHEMA_VERSION,
)

CLUSTER_NORMALIZATION_VERSION: Final[str] = "cluster_robust_normalization_v3"
CLUSTER_NORMALIZATION_CORPUS: Final[str] = "stage2636_04_curated_family_source_contract_corpus_v1"


@dataclass(frozen=True, slots=True)
class NormalizationStats:
    feature_id: str
    transform_id: str
    median: float
    iqr: float
    support_count: int
    expected_min: float
    expected_max: float


@dataclass(frozen=True, slots=True)
class NormalizedClusterVector:
    raw_vector: tuple[float, ...]
    assignment_vector: tuple[float, ...]
    unavailable_dimensions: tuple[str, ...]
    feature_schema_version: str
    normalization_version: str
    transform_ids: tuple[str, ...]
    support_counts: tuple[int, ...]
    vector_digest: str
    unavailable_reason: str = ""

    @property
    def available(self) -> bool:
        return self.unavailable_reason == "" and not self.unavailable_dimensions


_NORMALIZATION_STATS: Final[tuple[NormalizationStats, ...]] = (
    NormalizationStats("tag_count", "log1p_robust_tanh", 1.6094379124, 1.2527629685, 64, 0.0, 10000.0),
    NormalizationStats("tag_entropy", "bounded_unit", 0.0, 1.0, 64, 0.0, 8.0),
    NormalizationStats("unique_tag_count", "log1p_robust_tanh", 1.3862943611, 1.0986122887, 64, 0.0, 10000.0),
    NormalizationStats("graph_risk", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
    NormalizationStats("graph_anomaly", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
    NormalizationStats("temporal_belief", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
    NormalizationStats("markov_transition", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
    NormalizationStats("markov_rarity", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
    NormalizationStats("markov_pair_anomaly", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
    NormalizationStats("unity_context", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
    NormalizationStats("renpy_context", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
    NormalizationStats("rpgm_context", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
    NormalizationStats("media_context", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
    NormalizationStats("other_context", "bounded_unit", 0.0, 1.0, 64, 0.0, 1.0),
)

if tuple(row.feature_id for row in _NORMALIZATION_STATS) != tuple(spec.feature_id for spec in ASSIGNMENT_FEATURE_SPECS):
    raise RuntimeError("clustering normalization registry mismatch")


def _strict_finite_vector(value: object) -> tuple[tuple[float, ...], str]:
    items, reason = cluster_input_sequence(value, reason="cluster_vector_input_unavailable")
    if reason is not None:
        return (), reason
    if len(items) != RAW_FEATURE_COUNT:
        return (), "cluster_feature_dimension_mismatch"
    out: list[float] = []
    for item in items:
        if type(item) not in (int, float) or isinstance(item, bool):
            return (), "cluster_feature_non_numeric"
        number = float(item)
        if not math.isfinite(number):
            return (), "cluster_feature_nonfinite"
        out.append(number)
    return tuple(out), ""


def _assignment_vector_digest(assignment_vector: tuple[float, ...]) -> str:
    payload = {
        "feature_schema_version": CLUSTER_FEATURE_SCHEMA_VERSION,
        "normalization_version": CLUSTER_NORMALIZATION_VERSION,
        "assignment_vector": assignment_vector,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()


def _normalize_value(value: float, stats: NormalizationStats) -> float:
    bounded = min(stats.expected_max, max(stats.expected_min, value))
    if stats.transform_id == "log1p_robust_tanh":
        transformed = math.log1p(max(0.0, bounded))
        robust_z = (transformed - stats.median) / max(stats.iqr, 1e-9)
        return math.tanh(robust_z / 3.0)
    span = max(stats.expected_max - stats.expected_min, 1e-9)
    return (bounded - stats.expected_min) / span


def normalize_cluster_vector(
    value: object,
    *,
    feature_schema_version: object = CLUSTER_FEATURE_SCHEMA_VERSION,
) -> NormalizedClusterVector:
    if type(feature_schema_version) is not str or feature_schema_version != CLUSTER_FEATURE_SCHEMA_VERSION:
        published_schema = feature_schema_version if type(feature_schema_version) is str else ""
        return NormalizedClusterVector(
            (), (), (), published_schema, CLUSTER_NORMALIZATION_VERSION,
            (), (), "", "cluster_feature_schema_version_mismatch",
        )
    raw, reason = _strict_finite_vector(value)
    if reason:
        return NormalizedClusterVector(
            raw, (), (), CLUSTER_FEATURE_SCHEMA_VERSION, CLUSTER_NORMALIZATION_VERSION,
            tuple(row.transform_id for row in _NORMALIZATION_STATS),
            tuple(row.support_count for row in _NORMALIZATION_STATS),
            "", reason,
        )
    unavailable: list[str] = []
    normalized: list[float] = []
    for spec, stats in zip(ASSIGNMENT_FEATURE_SPECS, _NORMALIZATION_STATS, strict=True):
        value_at_index = raw[spec.index]
        if not math.isfinite(value_at_index):
            unavailable.append(spec.feature_id)
            normalized.append(0.0)
            continue
        normalized.append(_normalize_value(value_at_index, stats))
    digest = _assignment_vector_digest(tuple(normalized))
    return NormalizedClusterVector(
        raw,
        tuple(normalized),
        tuple(unavailable),
        CLUSTER_FEATURE_SCHEMA_VERSION,
        CLUSTER_NORMALIZATION_VERSION,
        tuple(row.transform_id for row in _NORMALIZATION_STATS),
        tuple(row.support_count for row in _NORMALIZATION_STATS),
        digest,
    )


def require_available_normalized_cluster_vector(
    value: object,
) -> NormalizedClusterVector:
    """Validate one exact immutable normalization result at model boundaries."""
    if type(value) is not NormalizedClusterVector:
        raise ValueError("cluster_normalized_vector_type_invalid")
    if value.unavailable_reason != "" or value.unavailable_dimensions != ():
        raise ValueError("cluster_normalized_vector_unavailable")
    if value.feature_schema_version != CLUSTER_FEATURE_SCHEMA_VERSION:
        raise ValueError("cluster_normalized_feature_schema_mismatch")
    if value.normalization_version != CLUSTER_NORMALIZATION_VERSION:
        raise ValueError("cluster_normalized_version_mismatch")
    expected_transforms = tuple(row.transform_id for row in _NORMALIZATION_STATS)
    expected_support = tuple(row.support_count for row in _NORMALIZATION_STATS)
    if type(value.transform_ids) is not tuple or value.transform_ids != expected_transforms:
        raise ValueError("cluster_normalized_transform_manifest_mismatch")
    if type(value.support_counts) is not tuple or value.support_counts != expected_support:
        raise ValueError("cluster_normalized_support_manifest_mismatch")
    for vector, expected, name in (
        (value.raw_vector, RAW_FEATURE_COUNT, "raw"),
        (value.assignment_vector, ASSIGNMENT_FEATURE_COUNT, "assignment"),
    ):
        if type(vector) is not tuple or len(vector) != expected:
            raise ValueError("cluster_normalized_" + name + "_dimension_mismatch")
        if any(
            type(item) not in (int, float) or isinstance(item, bool)
            or not math.isfinite(float(item))
            for item in vector
        ):
            raise ValueError("cluster_normalized_" + name + "_value_invalid")
    if value.vector_digest != _assignment_vector_digest(value.assignment_vector):
        raise ValueError("cluster_normalized_vector_digest_mismatch")
    return value


def normalization_manifest() -> tuple[NormalizationStats, ...]:
    return _NORMALIZATION_STATS


__all__ = (
    "CLUSTER_NORMALIZATION_CORPUS",
    "CLUSTER_NORMALIZATION_VERSION",
    "NormalizedClusterVector",
    "NormalizationStats",
    "normalization_manifest",
    "normalize_cluster_vector",
    "require_available_normalized_cluster_vector",
)
