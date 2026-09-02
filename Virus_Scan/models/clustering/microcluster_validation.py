"""Canonical in-memory microcluster admission contract."""
from __future__ import annotations
import math
from types import MappingProxyType
from typing import Final
from Virus_Scan.models.clustering.feature_registry import (
    ASSIGNMENT_FEATURE_COUNT,
    CLUSTER_FEATURE_SCHEMA_VERSION,
)
from Virus_Scan.models.clustering.microcluster_invariants import validate_microcluster_semantics
from Virus_Scan.models.clustering.normalization import CLUSTER_NORMALIZATION_VERSION
from Virus_Scan.models.clustering.policy import (
    CLUSTER_MODEL_VERSION,
    CLUSTER_POLICY,
    CLUSTER_STATE_SCHEMA_VERSION,
)
_MAPPING_PROXY_TYPE = type(MappingProxyType({}))
CANONICAL_SNAPSHOT_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version", "model_version", "feature_schema_version", "normalization_version",
    "cluster_id", "context_key", "centroid_vector", "dimension_count", "dimension_mean",
    "dimension_variance", "trusted_sample_count", "quarantined_sample_count", "samples",
    "malicious_samples", "benign_samples", "malicious_ratio", "benign_ratio", "label_support",
    "label_provenance", "tag_signature_counts", "chain_signature_counts",
    "behavior_signature_counts", "quarantine_tag_counts", "quarantine_chain_counts",
    "quarantine_behavior_counts", "tag_signature", "chain_signature", "behavior_signature",
    "members", "created_ordinal", "updated_ordinal", "created", "last_updated",
    "created_source", "last_updated_source", "retention_state", "kind", "confidence", "radius",
    "maximum_observed_distance", "drift_alarm", "purity_limit_exceeded", "influence_enabled",
    "last_known_good_centroid", "observation_digests", "last_assignment_evidence",
    "last_observed_kind", "last_update_authority", "last_update_applied",
    "last_update_rejected_reason", "normalization_vector_digest",
    "normalization_support_counts", "normalization_transform_ids", "unavailable_dimensions",
    "tag_evidence_summary", "tag_evidence_kinds_consumed", "last_assignment_threshold",
    "last_assignment_created", "update_authority_reason",
})
REQUIRED_SNAPSHOT_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version", "model_version", "feature_schema_version", "normalization_version",
    "cluster_id", "context_key", "centroid_vector", "dimension_count", "dimension_mean",
    "dimension_variance", "trusted_sample_count", "quarantined_sample_count", "samples",
    "malicious_samples", "benign_samples", "kind", "members", "created_ordinal",
    "updated_ordinal", "retention_state", "last_known_good_centroid", "observation_digests",
    "normalization_vector_digest", "normalization_support_counts", "normalization_transform_ids",
})
def _mapping(value: object) -> dict[str, object]:
    if type(value) is dict:
        return dict(value)
    if type(value) is _MAPPING_PROXY_TYPE:
        return dict(value)
    raise ValueError("microcluster_snapshot_not_mapping")
def _sequence(value: object, field_name: str) -> tuple[object, ...]:
    if type(value) is tuple:
        return value
    if type(value) is list:
        return tuple(value)
    raise ValueError(field_name + "_sequence_invalid")
def _finite_vector(value: object, field_name: str) -> tuple[float, ...]:
    items = _sequence(value, field_name)
    if len(items) != ASSIGNMENT_FEATURE_COUNT:
        raise ValueError(field_name + "_dimension_mismatch")
    result: list[float] = []
    for item in items:
        if type(item) not in (int, float) or isinstance(item, bool):
            raise ValueError(field_name + "_numeric_invalid")
        number = float(item)
        if not math.isfinite(number):
            raise ValueError(field_name + "_nonfinite")
        result.append(number)
    return tuple(result)
def _nonnegative_int(value: object, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(field_name + "_invalid")
    return value
def _exact_text(value: object, field_name: str) -> str:
    if type(value) is not str or str.strip(value) == "":
        raise ValueError(field_name + "_invalid")
    return value
def _bounded_texts(value: object, field_name: str, limit: int) -> tuple[str, ...]:
    if type(value) is frozenset:
        items = tuple(value)
    else:
        items = _sequence(value, field_name)
    if len(items) > limit:
        raise ValueError(field_name + "_limit_exceeded")
    for item in items:
        _exact_text(item, field_name)
    return tuple(items)
def _finite_scalar(
    value: object,
    field_name: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise ValueError(field_name + "_invalid")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(field_name + "_nonfinite")
    if minimum is not None and number < minimum:
        raise ValueError(field_name + "_below_minimum")
    if maximum is not None and number > maximum:
        raise ValueError(field_name + "_above_maximum")
    return number
def _bounded_pairs(
    value: object,
    field_name: str,
    limit: int,
    *,
    counts: bool = False,
) -> tuple[tuple[str, object], ...]:
    rows = _sequence(value, field_name)
    if len(rows) > limit:
        raise ValueError(field_name + "_limit_exceeded")
    out: list[tuple[str, object]] = []
    for raw in rows:
        row = _sequence(raw, field_name)
        if len(row) != 2:
            raise ValueError(field_name + "_row_invalid")
        key = _exact_text(row[0], field_name)
        item = row[1]
        if counts:
            item = _nonnegative_int(item, field_name)
        elif type(item) not in (str, bool, int, float) and item is not None:
            raise ValueError(field_name + "_value_invalid")
        elif type(item) is float and not math.isfinite(item):
            raise ValueError(field_name + "_value_nonfinite")
        out.append((key, item))
    return tuple(out)

def validate_microcluster_snapshot(snapshot: object, expected_cluster_id: str) -> dict[str, object]:
    """Reject any noncanonical snapshot before it can enter runtime state."""
    values = _mapping(snapshot)
    keys = frozenset(values)
    if not REQUIRED_SNAPSHOT_FIELDS <= keys or not keys <= CANONICAL_SNAPSHOT_FIELDS:
        raise ValueError("microcluster_snapshot_fields_invalid")
    if values.get("schema_version") != CLUSTER_STATE_SCHEMA_VERSION:
        raise ValueError("microcluster_schema_version_mismatch")
    if values.get("model_version") != CLUSTER_MODEL_VERSION:
        raise ValueError("microcluster_model_version_mismatch")
    if values.get("feature_schema_version") != CLUSTER_FEATURE_SCHEMA_VERSION:
        raise ValueError("microcluster_feature_schema_version_mismatch")
    if values.get("normalization_version") != CLUSTER_NORMALIZATION_VERSION:
        raise ValueError("microcluster_normalization_version_mismatch")
    cluster_id = _exact_text(values.get("cluster_id"), "microcluster_identity")
    if type(expected_cluster_id) is not str or cluster_id != expected_cluster_id:
        raise ValueError("microcluster_identity_mismatch")
    _exact_text(values.get("context_key"), "microcluster_context")
    for field_name in (
        "centroid_vector", "dimension_mean", "dimension_variance", "last_known_good_centroid",
    ):
        _finite_vector(values.get(field_name), field_name)
    dimension_count = _sequence(values.get("dimension_count"), "dimension_count")
    if len(dimension_count) != ASSIGNMENT_FEATURE_COUNT:
        raise ValueError("dimension_count_dimension_mismatch")
    for item in dimension_count:
        _nonnegative_int(item, "dimension_count")
    support_counts = _sequence(
        values.get("normalization_support_counts"), "normalization_support_counts",
    )
    if len(support_counts) != ASSIGNMENT_FEATURE_COUNT:
        raise ValueError("normalization_support_counts_dimension_mismatch")
    for item in support_counts:
        _nonnegative_int(item, "normalization_support_counts")
    transforms = _bounded_texts(
        values.get("normalization_transform_ids"),
        "normalization_transform_ids",
        ASSIGNMENT_FEATURE_COUNT,
    )
    if len(transforms) != ASSIGNMENT_FEATURE_COUNT:
        raise ValueError("normalization_transform_ids_dimension_mismatch")
    counts = {
        name: _nonnegative_int(values.get(name), name)
        for name in (
            "trusted_sample_count", "quarantined_sample_count", "samples",
            "malicious_samples", "benign_samples", "created_ordinal", "updated_ordinal",
        )
    }
    if counts["trusted_sample_count"] + counts["quarantined_sample_count"] > counts["samples"]:
        raise ValueError("microcluster_sample_counts_inconsistent")
    if counts["malicious_samples"] + counts["benign_samples"] > counts["trusted_sample_count"]:
        raise ValueError("microcluster_label_counts_inconsistent")
    if any(item != counts["trusted_sample_count"] for item in dimension_count):
        raise ValueError("dimension_count_support_mismatch")
    if values.get("kind") not in {"benign", "malicious", "mixed"}:
        raise ValueError("microcluster_kind_invalid")
    if values.get("retention_state") not in {"active", "quarantined", "retired"}:
        raise ValueError("microcluster_retention_state_invalid")
    _bounded_texts(values.get("members"), "members", CLUSTER_POLICY.maximum_members)
    _bounded_texts(
        values.get("observation_digests"),
        "observation_digests",
        CLUSTER_POLICY.maximum_observation_digests,
    )
    _exact_text(values.get("normalization_vector_digest"), "normalization_vector_digest")
    for field_name in ("tag_signature", "chain_signature", "behavior_signature"):
        if field_name in values:
            _bounded_texts(values[field_name], field_name, CLUSTER_POLICY.maximum_signature_terms)
    for field_name in (
        "label_provenance", "unavailable_dimensions", "tag_evidence_kinds_consumed",
    ):
        if field_name in values:
            _bounded_texts(values[field_name], field_name, 16)
    for field_name in (
        "tag_signature_counts", "chain_signature_counts", "behavior_signature_counts",
        "quarantine_tag_counts", "quarantine_chain_counts", "quarantine_behavior_counts",
    ):
        if field_name in values:
            _bounded_pairs(
                values[field_name], field_name, CLUSTER_POLICY.maximum_signature_terms,
                counts=True,
            )
    if "label_support" in values:
        _bounded_pairs(values["label_support"], "label_support", 4, counts=True)
    for field_name in ("last_assignment_evidence", "tag_evidence_summary"):
        if field_name in values:
            _bounded_pairs(values[field_name], field_name, 64)
    for field_name in ("malicious_ratio", "benign_ratio", "confidence"):
        if field_name in values:
            _finite_scalar(values[field_name], field_name, minimum=0.0, maximum=1.0)
    for field_name in (
        "created", "last_updated", "radius", "maximum_observed_distance",
        "last_assignment_threshold",
    ):
        if field_name in values:
            _finite_scalar(values[field_name], field_name, minimum=0.0)
    for field_name in (
        "drift_alarm", "purity_limit_exceeded", "influence_enabled",
        "last_update_applied", "last_assignment_created",
    ):
        if field_name in values and type(values[field_name]) is not bool:
            raise ValueError(field_name + "_invalid")
    for field_name in (
        "created_source", "last_updated_source", "last_observed_kind",
        "last_update_authority", "last_update_rejected_reason", "update_authority_reason",
    ):
        if field_name in values and type(values[field_name]) is not str:
            raise ValueError(field_name + "_invalid")
    validate_microcluster_semantics(values)
    return values
__all__ = (
    "CANONICAL_SNAPSHOT_FIELDS",
    "REQUIRED_SNAPSHOT_FIELDS",
    "validate_microcluster_snapshot",
)
