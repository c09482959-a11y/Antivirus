"""Trusted and quarantined observation update owner for microclusters."""
from __future__ import annotations

import math

from Virus_Scan.models.clustering.feature_registry import CLUSTER_FEATURE_SCHEMA_VERSION
from Virus_Scan.models.clustering.microcluster import TRUSTED_BENIGN, TRUSTED_MALICIOUS
from Virus_Scan.models.clustering.microcluster_validation import validate_microcluster_snapshot
from Virus_Scan.models.clustering.microcluster_values import (
    finite_microcluster_value,
    finite_microcluster_vector,
    freeze_microcluster_snapshot,
    increment_microcluster_counts,
    microcluster_distance,
    microcluster_mapping,
    microcluster_member_set,
    microcluster_signature_terms,
    nonnegative_microcluster_int,
)
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


def update_microcluster_snapshot(
    snapshot: object,
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
    assignment_similarity: float,
    assignment_evidence: object = (),
    label_provenance: object = (),
) -> object:
    normalized = require_available_normalized_cluster_vector(normalized)
    current = microcluster_mapping(snapshot)
    cluster_id = current.get("cluster_id")
    if type(cluster_id) is not str or cluster_id == "":
        raise ValueError("microcluster_identity_invalid")
    current = validate_microcluster_snapshot(snapshot, cluster_id)
    expected = len(normalized.assignment_vector)
    mean = finite_microcluster_vector(
        current.get("dimension_mean", current.get("centroid_vector", ())), expected,
    )
    variance = finite_microcluster_vector(current.get("dimension_variance", ()), expected)
    if not mean:
        mean = tuple(normalized.assignment_vector)
    if not variance:
        variance = tuple(0.0 for _ in mean)
    trusted_count = nonnegative_microcluster_int(current.get("trusted_sample_count"))
    quarantined_count = nonnegative_microcluster_int(current.get("quarantined_sample_count"))
    samples = nonnegative_microcluster_int(current.get("samples")) + 1
    malicious_samples = nonnegative_microcluster_int(current.get("malicious_samples"))
    benign_samples = nonnegative_microcluster_int(current.get("benign_samples"))
    radius, diagonal = microcluster_distance(normalized.assignment_vector, mean, variance)
    trusted_authority = authority in (TRUSTED_BENIGN, TRUSTED_MALICIOUS)
    outlier = trusted_count > 0 and (
        assignment_similarity < CLUSTER_POLICY.trusted_update_similarity_gate
        or diagonal > CLUSTER_POLICY.maximum_diagonal_distance
    )
    apply_update = trusted_authority and not outlier
    if apply_update:
        if trusted_count == 0:
            mean = tuple(normalized.assignment_vector)
            variance = tuple(0.0 for _ in mean)
            trusted_count = 1
        else:
            alpha = min(
                CLUSTER_POLICY.maximum_update_influence,
                1.0 / float(trusted_count + 1),
            )
            new_mean = tuple(
                old + alpha * (value - old)
                for old, value in zip(mean, normalized.assignment_vector, strict=True)
            )
            variance = tuple(
                max(0.0, (1.0 - alpha) * (old_var + alpha * (value - old) ** 2))
                for old_var, old, value in zip(
                    variance, mean, normalized.assignment_vector, strict=True,
                )
            )
            mean = new_mean
            trusted_count += 1
        if authority == TRUSTED_BENIGN:
            benign_samples += 1
        else:
            malicious_samples += 1
    else:
        quarantined_count = min(
            CLUSTER_POLICY.maximum_quarantined_samples, quarantined_count + 1,
        )
    trusted_tags = current.get("tag_signature_counts", ())
    trusted_chains = current.get("chain_signature_counts", ())
    trusted_behaviors = current.get("behavior_signature_counts", ())
    quarantine_tags = current.get("quarantine_tag_counts", ())
    quarantine_chains = current.get("quarantine_chain_counts", ())
    quarantine_behaviors = current.get("quarantine_behavior_counts", ())
    if apply_update:
        trusted_tags = increment_microcluster_counts(trusted_tags, tags)
        trusted_chains = increment_microcluster_counts(trusted_chains, chains)
        trusted_behaviors = increment_microcluster_counts(trusted_behaviors, behaviors)
    else:
        quarantine_tags = increment_microcluster_counts(quarantine_tags, tags)
        quarantine_chains = increment_microcluster_counts(quarantine_chains, chains)
        quarantine_behaviors = increment_microcluster_counts(quarantine_behaviors, behaviors)
    labelled = malicious_samples + benign_samples
    malicious_ratio = malicious_samples / labelled if labelled else 0.0
    benign_ratio = benign_samples / labelled if labelled else 0.0
    purity = max(malicious_ratio, benign_ratio) if labelled else 0.0
    maximum_distance = max(
        finite_microcluster_value(current.get("maximum_observed_distance")),
        0.0 if not math.isfinite(radius) else radius,
    )
    previous_radius = finite_microcluster_value(current.get("radius"))
    current_radius = max(
        previous_radius,
        0.0 if not apply_update or not math.isfinite(radius) else radius,
    )
    drift_alarm = current_radius > CLUSTER_POLICY.maximum_radius
    purity_limit_exceeded = labelled >= CLUSTER_POLICY.minimum_trusted_support and purity < 0.70
    kind = "mixed"
    if malicious_samples > benign_samples and malicious_samples > 0:
        kind = "malicious"
    elif benign_samples > malicious_samples and benign_samples > 0:
        kind = "benign"
    support_confidence = min(
        1.0, trusted_count / float(CLUSTER_POLICY.minimum_trusted_support),
    )
    quarantine_ratio = quarantined_count / max(1.0, float(samples))
    dispersion_factor = max(
        0.0,
        1.0 - min(1.0, current_radius / max(CLUSTER_POLICY.maximum_radius, 1e-9)),
    )
    confidence = max(
        0.0,
        min(
            1.0,
            support_confidence * purity * dispersion_factor * (1.0 - 0.5 * quarantine_ratio),
        ),
    )
    influence_enabled = (
        trusted_count >= CLUSTER_POLICY.minimum_trusted_support
        and not drift_alarm
        and not purity_limit_exceeded
    )
    members = microcluster_member_set(current.get("members", ()))
    if node:
        members = frozenset((*members, node))
    if len(members) > CLUSTER_POLICY.maximum_members:
        members = frozenset(sorted(members)[:CLUSTER_POLICY.maximum_members])
    digests = tuple(dict.fromkeys((
        *tuple(item for item in current.get("observation_digests", ()) if type(item) is str),
        observation_digest,
    )))
    digests = tuple(item for item in digests if item)[
        -CLUSTER_POLICY.maximum_observation_digests:
    ]
    last_good = finite_microcluster_vector(
        current.get("last_known_good_centroid", mean), expected,
    ) or mean
    if apply_update and not drift_alarm and not purity_limit_exceeded:
        last_good = mean
    prior_provenance = tuple(
        item for item in current.get("label_provenance", ()) if type(item) is str and item != ""
    )
    new_provenance = tuple(
        item for item in label_provenance if type(item) is str and item != ""
    ) if type(label_provenance) in (tuple, list, set, frozenset) else ()
    current.update({
        "schema_version": CLUSTER_STATE_SCHEMA_VERSION,
        "model_version": CLUSTER_MODEL_VERSION,
        "feature_schema_version": CLUSTER_FEATURE_SCHEMA_VERSION,
        "normalization_version": CLUSTER_NORMALIZATION_VERSION,
        "centroid_vector": tuple(mean),
        "dimension_count": tuple(trusted_count for _ in mean),
        "dimension_mean": tuple(mean),
        "dimension_variance": tuple(variance),
        "trusted_sample_count": trusted_count,
        "quarantined_sample_count": quarantined_count,
        "samples": samples,
        "malicious_samples": malicious_samples,
        "benign_samples": benign_samples,
        "malicious_ratio": malicious_ratio,
        "benign_ratio": benign_ratio,
        "label_support": tuple(sorted((('benign', benign_samples), ('malicious', malicious_samples)))),
        "label_provenance": tuple(sorted(set((*prior_provenance, *new_provenance)))) if apply_update else prior_provenance,
        "tag_signature_counts": trusted_tags,
        "chain_signature_counts": trusted_chains,
        "behavior_signature_counts": trusted_behaviors,
        "quarantine_tag_counts": quarantine_tags,
        "quarantine_chain_counts": quarantine_chains,
        "quarantine_behavior_counts": quarantine_behaviors,
        "tag_signature": microcluster_signature_terms(
            trusted_tags, () if trusted_count else quarantine_tags,
        ),
        "chain_signature": microcluster_signature_terms(
            trusted_chains, () if trusted_count else quarantine_chains,
        ),
        "behavior_signature": microcluster_signature_terms(
            trusted_behaviors, () if trusted_count else quarantine_behaviors,
        ),
        "members": members,
        "updated_ordinal": ordinal,
        "last_updated": float(ordinal),
        "last_updated_source": "deterministic_learning_decision_ordinal",
        "kind": kind,
        "confidence": confidence,
        "radius": current_radius,
        "maximum_observed_distance": maximum_distance,
        "drift_alarm": drift_alarm,
        "purity_limit_exceeded": purity_limit_exceeded,
        "influence_enabled": influence_enabled,
        "retention_state": "quarantined" if drift_alarm or purity_limit_exceeded else "active",
        "last_known_good_centroid": tuple(last_good),
        "observation_digests": digests,
        "last_assignment_evidence": tuple(assignment_evidence) if type(assignment_evidence) in (tuple, list) else (),
        "last_observed_kind": observed_kind,
        "last_update_authority": authority,
        "last_update_applied": apply_update,
        "last_update_rejected_reason": "outlier_update_gate" if outlier else "" if apply_update else "observation_quarantined",
        "normalization_vector_digest": normalized.vector_digest,
        "normalization_support_counts": normalized.support_counts,
        "normalization_transform_ids": normalized.transform_ids,
        "unavailable_dimensions": normalized.unavailable_dimensions,
    })
    frozen = freeze_microcluster_snapshot(current)
    validate_microcluster_snapshot(frozen, cluster_id)
    return frozen


__all__ = ("update_microcluster_snapshot",)
