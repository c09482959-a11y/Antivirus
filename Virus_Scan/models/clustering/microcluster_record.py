"""Exact current-schema persisted microcluster record validation owner."""
from __future__ import annotations

import math
from Virus_Scan.models.clustering.feature_registry import (
    ASSIGNMENT_FEATURE_COUNT,
    CLUSTER_FEATURE_SCHEMA_VERSION,
)
from Virus_Scan.models.clustering.microcluster_values import (
    freeze_microcluster_snapshot,
    microcluster_text,
)
from Virus_Scan.models.clustering.normalization import CLUSTER_NORMALIZATION_VERSION
from Virus_Scan.models.clustering.microcluster_validation import (
    CANONICAL_SNAPSHOT_FIELDS,
    REQUIRED_SNAPSHOT_FIELDS,
    validate_microcluster_snapshot,
)
from Virus_Scan.models.clustering.policy import (
    CLUSTER_MODEL_VERSION,
    CLUSTER_POLICY,
    CLUSTER_STATE_SCHEMA_VERSION,
)

def _record_sequence(value: object) -> tuple[object, ...]:
    if type(value) is list:
        return tuple(value)
    if type(value) is tuple:
        return value
    raise ValueError("microcluster_sequence_invalid")


def _record_vector(value: object, expected: int, field_name: str) -> tuple[float, ...]:
    values = _record_sequence(value)
    if len(values) != expected:
        raise ValueError(field_name + "_dimension_mismatch")
    out: list[float] = []
    for item in values:
        if type(item) not in (int, float) or isinstance(item, bool):
            raise ValueError(field_name + "_numeric_invalid")
        number = float(item)
        if not math.isfinite(number):
            raise ValueError(field_name + "_nonfinite")
        out.append(number)
    return tuple(out)


def _record_nonnegative_int(value: object, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(field_name + "_invalid")
    return value


def _record_finite(value: object, field_name: str) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise ValueError(field_name + "_invalid")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(field_name + "_nonfinite")
    return number


def _record_texts(value: object, field_name: str, *, limit: int) -> tuple[str, ...]:
    values = _record_sequence(value)
    if len(values) > limit:
        raise ValueError(field_name + "_limit_exceeded")
    out: list[str] = []
    for item in values:
        text = microcluster_text(item)
        if text == "":
            raise ValueError(field_name + "_text_invalid")
        out.append(text)
    return tuple(out)


def _record_pairs(value: object, field_name: str, *, limit: int) -> tuple[tuple[str, object], ...]:
    rows = _record_sequence(value)
    if len(rows) > limit:
        raise ValueError(field_name + "_limit_exceeded")
    out: list[tuple[str, object]] = []
    for raw in rows:
        row = _record_sequence(raw)
        if len(row) != 2:
            raise ValueError(field_name + "_row_invalid")
        key = microcluster_text(row[0])
        if key == "":
            raise ValueError(field_name + "_key_invalid")
        value_item = row[1]
        if type(value_item) not in (str, bool, int, float) and value_item is not None:
            raise ValueError(field_name + "_value_invalid")
        if type(value_item) is float and not math.isfinite(value_item):
            raise ValueError(field_name + "_value_nonfinite")
        out.append((key, value_item))
    return tuple(out)


def microcluster_from_record(record: object, expected_cluster_id: str) -> object:
    """Validate and freeze one exact current-schema persisted microcluster."""
    if type(record) is not dict:
        raise ValueError("microcluster_record_not_object")
    keys = frozenset(record)
    if not REQUIRED_SNAPSHOT_FIELDS <= keys or not keys <= CANONICAL_SNAPSHOT_FIELDS:
        raise ValueError("microcluster_record_fields_invalid")
    if record.get("schema_version") != CLUSTER_STATE_SCHEMA_VERSION:
        raise ValueError("microcluster_schema_version_mismatch")
    if record.get("model_version") != CLUSTER_MODEL_VERSION:
        raise ValueError("microcluster_model_version_mismatch")
    if record.get("feature_schema_version") != CLUSTER_FEATURE_SCHEMA_VERSION:
        raise ValueError("microcluster_feature_schema_version_mismatch")
    if record.get("normalization_version") != CLUSTER_NORMALIZATION_VERSION:
        raise ValueError("microcluster_normalization_version_mismatch")
    cluster_id = microcluster_text(record.get("cluster_id"))
    if cluster_id == "" or cluster_id != expected_cluster_id:
        raise ValueError("microcluster_identity_mismatch")
    if microcluster_text(record.get("context_key")) == "":
        raise ValueError("microcluster_context_invalid")
    expected = len(record.get("normalization_support_counts", ()))
    if expected <= 0:
        raise ValueError("microcluster_dimension_count_invalid")
    if expected != ASSIGNMENT_FEATURE_COUNT:
        raise ValueError("microcluster_assignment_dimension_mismatch")
    values = dict(record)
    for field_name in ("centroid_vector", "dimension_mean", "dimension_variance", "last_known_good_centroid"):
        values[field_name] = _record_vector(record.get(field_name), expected, field_name)
    dimension_count = _record_sequence(record.get("dimension_count"))
    if len(dimension_count) != expected:
        raise ValueError("dimension_count_dimension_mismatch")
    values["dimension_count"] = tuple(
        _record_nonnegative_int(item, "dimension_count") for item in dimension_count
    )
    for field_name in (
        "trusted_sample_count", "quarantined_sample_count", "samples", "malicious_samples",
        "benign_samples", "created_ordinal", "updated_ordinal",
    ):
        values[field_name] = _record_nonnegative_int(record.get(field_name), field_name)
    if values["trusted_sample_count"] + values["quarantined_sample_count"] > values["samples"]:
        raise ValueError("microcluster_sample_counts_inconsistent")
    for field_name in (
        "malicious_ratio", "benign_ratio", "created", "last_updated", "confidence", "radius",
        "maximum_observed_distance", "last_assignment_threshold",
    ):
        if field_name in record:
            values[field_name] = _record_finite(record[field_name], field_name)
    for field_name in (
        "drift_alarm", "purity_limit_exceeded", "influence_enabled",
        "last_update_applied", "last_assignment_created",
    ):
        if field_name in record and type(record[field_name]) is not bool:
            raise ValueError(field_name + "_invalid")
    kind = microcluster_text(record.get("kind"))
    if kind not in {"benign", "malicious", "mixed"}:
        raise ValueError("microcluster_kind_invalid")
    retention_state = microcluster_text(record.get("retention_state"))
    if retention_state not in {"active", "quarantined", "retired"}:
        raise ValueError("microcluster_retention_state_invalid")
    values["kind"] = kind
    values["retention_state"] = retention_state
    values["members"] = frozenset(_record_texts(
        record.get("members"), "members", limit=CLUSTER_POLICY.maximum_members,
    ))
    for field_name in ("tag_signature", "chain_signature", "behavior_signature"):
        if field_name in record:
            values[field_name] = frozenset(_record_texts(
                record[field_name], field_name, limit=CLUSTER_POLICY.maximum_signature_terms,
            ))
    for field_name in (
        "tag_signature_counts", "chain_signature_counts", "behavior_signature_counts",
        "quarantine_tag_counts", "quarantine_chain_counts", "quarantine_behavior_counts",
    ):
        if field_name in record:
            pairs = _record_pairs(
                record[field_name], field_name, limit=CLUSTER_POLICY.maximum_signature_terms,
            )
            if any(type(value) is not int or value < 0 for _key, value in pairs):
                raise ValueError(field_name + "_count_invalid")
            values[field_name] = tuple((key, int(value)) for key, value in pairs)
    for field_name, limit in (
        ("label_support", 4), ("last_assignment_evidence", 64), ("tag_evidence_summary", 64),
    ):
        if field_name in record:
            values[field_name] = _record_pairs(record[field_name], field_name, limit=limit)
    for field_name, limit in (
        ("label_provenance", 16),
        ("observation_digests", CLUSTER_POLICY.maximum_observation_digests),
        ("normalization_transform_ids", expected), ("unavailable_dimensions", expected),
        ("tag_evidence_kinds_consumed", 16),
    ):
        if field_name in record:
            values[field_name] = _record_texts(record[field_name], field_name, limit=limit)
    support_counts = _record_sequence(record.get("normalization_support_counts"))
    if len(support_counts) != expected:
        raise ValueError("normalization_support_counts_dimension_mismatch")
    values["normalization_support_counts"] = tuple(
        _record_nonnegative_int(item, "normalization_support_counts") for item in support_counts
    )
    for field_name in (
        "created_source", "last_updated_source", "last_observed_kind", "last_update_authority",
        "last_update_rejected_reason", "normalization_vector_digest", "update_authority_reason",
    ):
        if field_name in record:
            values[field_name] = microcluster_text(record[field_name])
    validate_microcluster_snapshot(values, expected_cluster_id)
    return freeze_microcluster_snapshot(values)


__all__ = ("microcluster_from_record",)
