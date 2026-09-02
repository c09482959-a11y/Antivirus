"""Canonical immutable online microcluster snapshot and atomic commit owner."""
from __future__ import annotations

from typing import Final

from Virus_Scan.models.clustering.feature_registry import CLUSTER_FEATURE_SCHEMA_VERSION
from Virus_Scan.models.clustering.microcluster_values import (
    freeze_microcluster_snapshot as _freeze_snapshot,
    increment_microcluster_counts as _increment_counts,
    microcluster_mapping as _microcluster_mapping,
    microcluster_member_set as _member_set,
    microcluster_signature_terms as _signature_terms,
    microcluster_text as _text,
    microcluster_text_set as _text_set,
)
from Virus_Scan.models.clustering.microcluster_validation import validate_microcluster_snapshot
from Virus_Scan.models.clustering.normalization import (
    CLUSTER_NORMALIZATION_VERSION,
    NormalizedClusterVector,
    require_available_normalized_cluster_vector,
)
from Virus_Scan.models.clustering.policy import (
    CLUSTER_MODEL_VERSION,
    CLUSTER_POLICY,
    CLUSTER_STATE_SCHEMA_VERSION,
)
from Virus_Scan.models.clustering.state import (
    benign_clusters,
    cluster_metadata,
    cluster_signatures,
    cluster_tag_signatures,
    malicious_clusters,
    mixed_clusters,
)

TRUSTED_BENIGN: Final[str] = "trusted_benign"
TRUSTED_MALICIOUS: Final[str] = "trusted_malicious"
QUARANTINED: Final[str] = "quarantined"


def empty_microcluster_snapshot(
    cluster_id: str,
    context_key: str,
    normalized: NormalizedClusterVector,
    *,
    node: str,
    observation_digest: str,
    authority: str,
    observed_kind: str,
    tags: object,
    chains: object,
    behaviors: object,
    ordinal: int,
    assignment_evidence: object = (),
    label_provenance: object = (),
) -> object:
    normalized = require_available_normalized_cluster_vector(normalized)
    vector = normalized.assignment_vector
    trusted = authority in (TRUSTED_BENIGN, TRUSTED_MALICIOUS)
    trusted_count = 1 if trusted else 0
    quarantined_count = 0 if trusted else 1
    dimension_count = tuple(1 if trusted else 0 for _ in vector)
    variance = tuple(0.0 for _ in vector)
    trusted_tags = _increment_counts((), tags) if trusted else ()
    trusted_chains = _increment_counts((), chains) if trusted else ()
    trusted_behaviors = _increment_counts((), behaviors) if trusted else ()
    quarantine_tags = _increment_counts((), tags) if not trusted else ()
    quarantine_chains = _increment_counts((), chains) if not trusted else ()
    quarantine_behaviors = _increment_counts((), behaviors) if not trusted else ()
    benign_samples = 1 if authority == TRUSTED_BENIGN else 0
    malicious_samples = 1 if authority == TRUSTED_MALICIOUS else 0
    kind = "benign" if benign_samples else "malicious" if malicious_samples else "mixed"
    confidence = min(1.0, trusted_count / float(CLUSTER_POLICY.minimum_trusted_support))
    values = {
        "schema_version": CLUSTER_STATE_SCHEMA_VERSION,
        "model_version": CLUSTER_MODEL_VERSION,
        "feature_schema_version": CLUSTER_FEATURE_SCHEMA_VERSION,
        "normalization_version": CLUSTER_NORMALIZATION_VERSION,
        "cluster_id": cluster_id,
        "context_key": context_key,
        "centroid_vector": tuple(vector),
        "dimension_count": dimension_count,
        "dimension_mean": tuple(vector),
        "dimension_variance": variance,
        "trusted_sample_count": trusted_count,
        "quarantined_sample_count": quarantined_count,
        "samples": 1,
        "malicious_samples": malicious_samples,
        "benign_samples": benign_samples,
        "malicious_ratio": float(malicious_samples),
        "benign_ratio": float(benign_samples),
        "label_support": tuple(sorted((('benign', benign_samples), ('malicious', malicious_samples)))),
        "label_provenance": tuple(sorted(
            item for item in label_provenance
            if type(item) is str and item != ""
        )) if trusted and type(label_provenance) in (tuple, list, set, frozenset) else (),
        "tag_signature_counts": trusted_tags,
        "chain_signature_counts": trusted_chains,
        "behavior_signature_counts": trusted_behaviors,
        "quarantine_tag_counts": quarantine_tags,
        "quarantine_chain_counts": quarantine_chains,
        "quarantine_behavior_counts": quarantine_behaviors,
        "tag_signature": _signature_terms(
            trusted_tags, () if trusted_count else quarantine_tags,
        ),
        "chain_signature": _signature_terms(
            trusted_chains, () if trusted_count else quarantine_chains,
        ),
        "behavior_signature": _signature_terms(
            trusted_behaviors, () if trusted_count else quarantine_behaviors,
        ),
        "members": frozenset((node,)) if node else frozenset(),
        "created_ordinal": ordinal,
        "updated_ordinal": ordinal,
        "created": float(ordinal),
        "last_updated": float(ordinal),
        "created_source": "deterministic_learning_decision_ordinal",
        "last_updated_source": "deterministic_learning_decision_ordinal",
        "retention_state": "active",
        "kind": kind,
        "confidence": confidence,
        "radius": 0.0,
        "maximum_observed_distance": 0.0,
        "drift_alarm": False,
        "purity_limit_exceeded": False,
        "influence_enabled": trusted_count >= CLUSTER_POLICY.minimum_trusted_support,
        "last_known_good_centroid": tuple(vector),
        "observation_digests": (observation_digest,) if observation_digest else (),
        "last_assignment_evidence": tuple(assignment_evidence) if type(assignment_evidence) in (tuple, list) else (),
        "last_observed_kind": observed_kind,
        "last_update_authority": authority,
        "last_update_applied": trusted,
        "last_update_rejected_reason": "" if trusted else "observation_quarantined",
        "normalization_vector_digest": normalized.vector_digest,
        "normalization_support_counts": normalized.support_counts,
        "normalization_transform_ids": normalized.transform_ids,
        "unavailable_dimensions": normalized.unavailable_dimensions,
    }
    frozen = _freeze_snapshot(values)
    validate_microcluster_snapshot(frozen, cluster_id)
    return frozen


def microcluster_with_fields(snapshot: object, **fields: object) -> object:
    """Return a frozen candidate; admission occurs only through canonical validation."""
    values = _microcluster_mapping(snapshot)
    if not values:
        return _freeze_snapshot({})
    values.update(fields)
    return _freeze_snapshot(values)


def commit_microcluster_snapshot(cluster_id: str, snapshot: object) -> None:
    """Atomically publish the canonical snapshot and all deterministic indexes."""
    values = validate_microcluster_snapshot(snapshot, cluster_id)
    centroid = tuple(values.get("centroid_vector", ()))
    members = set(_member_set(values.get("members", ())))
    kind = _text(values.get("kind"), "mixed")
    cluster_metadata()[cluster_id] = snapshot
    cluster_signatures()[cluster_id] = list(centroid)
    cluster_tag_signatures()[cluster_id] = set(
        _text_set(values.get("tag_signature", ()))
    )
    malicious_clusters().pop(cluster_id, None)
    benign_clusters().pop(cluster_id, None)
    mixed_clusters().pop(cluster_id, None)
    if kind == "malicious":
        malicious_clusters()[cluster_id] = members
    elif kind == "benign":
        benign_clusters()[cluster_id] = members
    else:
        mixed_clusters()[cluster_id] = members


__all__ = (
    "QUARANTINED",
    "TRUSTED_BENIGN",
    "TRUSTED_MALICIOUS",
    "commit_microcluster_snapshot",
    "empty_microcluster_snapshot",
    "microcluster_with_fields",
)
