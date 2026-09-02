"""Semantic invariants for the canonical microcluster admission owner."""
from __future__ import annotations

import math
from typing import Final

from Virus_Scan.models.clustering.feature_registry import ASSIGNMENT_FEATURE_NAMES
from Virus_Scan.models.clustering.normalization import normalization_manifest
from Virus_Scan.models.clustering.policy import CLUSTER_POLICY

_DETERMINISTIC_ORDINAL_SOURCE: Final[str] = "deterministic_learning_decision_ordinal"
_UPDATE_AUTHORITIES: Final[frozenset[str]] = frozenset({
    "trusted_benign", "trusted_malicious", "quarantined",
})
_OBSERVED_KINDS: Final[frozenset[str]] = frozenset({"benign", "malicious", "mixed"})
_REJECTION_REASONS: Final[frozenset[str]] = frozenset({
    "", "observation_quarantined", "outlier_update_gate",
})
_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdef")


def _exact_tuple(value: object, field_name: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise ValueError(field_name + "_tuple_invalid")
    return value


def _bounded_vector(
    value: object,
    field_name: str,
    *,
    minimum: float,
    maximum: float,
) -> tuple[float, ...]:
    values = _exact_tuple(value, field_name)
    result: list[float] = []
    for item in values:
        if type(item) not in (int, float) or isinstance(item, bool):
            raise ValueError(field_name + "_numeric_invalid")
        number = float(item)
        if not math.isfinite(number):
            raise ValueError(field_name + "_nonfinite")
        if number < minimum or number > maximum:
            raise ValueError(field_name + "_range_invalid")
        result.append(number)
    return tuple(result)


def _exact_text(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise ValueError(field_name + "_invalid")
    return value


def validate_microcluster_semantics(values: dict[str, object]) -> None:
    """Reject semantically inconsistent current-schema snapshot evidence."""
    manifest = normalization_manifest()
    expected_transforms = tuple(row.transform_id for row in manifest)
    expected_support = tuple(row.support_count for row in manifest)
    if values.get("normalization_transform_ids") != expected_transforms:
        raise ValueError("normalization_transform_manifest_mismatch")
    if values.get("normalization_support_counts") != expected_support:
        raise ValueError("normalization_support_manifest_mismatch")

    unavailable = _exact_tuple(values.get("unavailable_dimensions", ()), "unavailable_dimensions")
    if len(set(unavailable)) != len(unavailable) or any(
        type(item) is not str or item not in ASSIGNMENT_FEATURE_NAMES for item in unavailable
    ):
        raise ValueError("unavailable_dimensions_registry_mismatch")

    digest = _exact_text(values.get("normalization_vector_digest"), "normalization_vector_digest")
    if len(digest) != 64 or any(character not in _HEX_DIGITS for character in digest):
        raise ValueError("normalization_vector_digest_invalid")

    centroid = _bounded_vector(
        values.get("centroid_vector"), "centroid_vector", minimum=-1.0, maximum=1.0,
    )
    mean = _bounded_vector(
        values.get("dimension_mean"), "dimension_mean", minimum=-1.0, maximum=1.0,
    )
    _bounded_vector(
        values.get("last_known_good_centroid"),
        "last_known_good_centroid",
        minimum=-1.0,
        maximum=1.0,
    )
    _bounded_vector(
        values.get("dimension_variance"), "dimension_variance", minimum=0.0, maximum=4.0,
    )
    if centroid != mean:
        raise ValueError("microcluster_centroid_mean_mismatch")

    created_ordinal = values.get("created_ordinal")
    updated_ordinal = values.get("updated_ordinal")
    if type(created_ordinal) is not int or type(updated_ordinal) is not int:
        raise ValueError("microcluster_ordinal_invalid")
    if updated_ordinal < created_ordinal:
        raise ValueError("microcluster_ordinal_order_invalid")
    if values.get("created") != float(created_ordinal):
        raise ValueError("microcluster_created_ordinal_mismatch")
    if values.get("last_updated") != float(updated_ordinal):
        raise ValueError("microcluster_updated_ordinal_mismatch")
    for field_name in ("created_source", "last_updated_source"):
        if values.get(field_name) != _DETERMINISTIC_ORDINAL_SOURCE:
            raise ValueError(field_name + "_invalid")

    if values.get("last_observed_kind") not in _OBSERVED_KINDS:
        raise ValueError("last_observed_kind_invalid")
    if values.get("last_update_authority") not in _UPDATE_AUTHORITIES:
        raise ValueError("last_update_authority_invalid")
    if values.get("last_update_rejected_reason") not in _REJECTION_REASONS:
        raise ValueError("last_update_rejected_reason_invalid")

    radius = values.get("radius", 0.0)
    maximum_distance = values.get("maximum_observed_distance", 0.0)
    if type(radius) not in (int, float) or type(maximum_distance) not in (int, float):
        raise ValueError("microcluster_distance_invalid")
    if float(radius) > float(maximum_distance):
        raise ValueError("microcluster_radius_exceeds_observed_distance")
    if values.get("drift_alarm") is not (float(radius) > CLUSTER_POLICY.maximum_radius):
        raise ValueError("microcluster_drift_alarm_mismatch")


__all__ = ("validate_microcluster_semantics",)
