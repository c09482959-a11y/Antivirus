"""Versioned hybrid similarity evidence for canonical microclusters."""
from __future__ import annotations

from dataclasses import dataclass
import math

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.models.clustering.chain_signatures import (
    cluster_behavior_signature,
    cluster_chain_signature,
)
from Virus_Scan.models.clustering.common import (
    cluster_text_set,
    finite_cluster_metric,
)
from Virus_Scan.models.clustering.microcluster_values import (
    microcluster_mapping,
    microcluster_value,
    nonnegative_microcluster_int,
)
from Virus_Scan.models.clustering.policy import (
    CLUSTER_POLICY,
    CLUSTER_SIMILARITY_VERSION,
    ClusterPolicyManifest,
)
from Virus_Scan.models.clustering.vectors import cosine_similarity


@dataclass(frozen=True, slots=True)
class ClusterSimilarityEvidence:
    score: float
    cosine: float
    mahalanobis: float
    tag_jaccard: float
    chain_jaccard: float
    behavior_jaccard: float
    component_coverage: float
    support_confidence: float
    diagonal_distance: float
    version: str = CLUSTER_SIMILARITY_VERSION

    def as_pairs(self) -> tuple[tuple[str, object], ...]:
        return (
            ("score", self.score),
            ("cosine", self.cosine),
            ("mahalanobis", self.mahalanobis),
            ("tag_jaccard", self.tag_jaccard),
            ("chain_jaccard", self.chain_jaccard),
            ("behavior_jaccard", self.behavior_jaccard),
            ("component_coverage", self.component_coverage),
            ("support_confidence", self.support_confidence),
            ("diagonal_distance", self.diagonal_distance),
            ("version", self.version),
        )


def cluster_jaccard_similarity(a: object, b: object) -> float:
    left = cluster_text_set(a, reason="cluster_jaccard_left_unavailable")
    right = cluster_text_set(b, reason="cluster_jaccard_right_unavailable")
    if not left and not right:
        return 0.0
    return len(left & right) / max(1, len(left | right))


def _finite_vector(value: object) -> tuple[float, ...]:
    if type(value) not in (tuple, list):
        return ()
    result: list[float] = []
    for item in value:
        if type(item) not in (int, float) or isinstance(item, bool):
            return ()
        number = float(item)
        if not math.isfinite(number):
            return ()
        result.append(number)
    return tuple(result)


def _diagonal_similarity(
    vector: tuple[float, ...],
    meta: object,
) -> tuple[float, float, bool]:
    mean = _finite_vector(microcluster_value(meta, "dimension_mean", ()))
    variance = _finite_vector(microcluster_value(meta, "dimension_variance", ()))
    if len(vector) == 0 or len(vector) != len(mean) or len(mean) != len(variance):
        return 0.0, math.inf, False
    standardized = [
        ((value - center) ** 2) / max(var, 0.0025)
        for value, center, var in zip(vector, mean, variance, strict=True)
    ]
    distance = math.sqrt(sum(standardized) / max(1, len(standardized)))
    return 1.0 / (1.0 + distance), distance, True


def _sequence_evidence_available(value: object) -> bool:
    """Return availability without probing caller-owned container hooks."""
    return type(value) in (tuple, list, set, frozenset)


def cluster_similarity_evidence(
    feature_vector: object,
    centroid: object,
    chain_evidence: ChainEvidence,
    tags: object = None,
    meta: object = None,
    node: object = None,
    *,
    policy: ClusterPolicyManifest = CLUSTER_POLICY,
) -> ClusterSimilarityEvidence:
    del node
    feature_values = _finite_vector(feature_vector)
    centroid_values = _finite_vector(centroid)
    cosine_available = (
        len(feature_values) > 0 and len(feature_values) == len(centroid_values)
    )
    cosine = (
        cosine_similarity(feature_values, centroid_values)
        if cosine_available else 0.0
    )
    mahalanobis, diagonal_distance, mahalanobis_available = _diagonal_similarity(
        feature_values, meta,
    )
    meta_values = microcluster_mapping(meta)
    tag_available = (
        _sequence_evidence_available(tags)
        and "tag_signature" in meta_values
        and _sequence_evidence_available(meta_values["tag_signature"])
    )
    chain_available = (
        type(chain_evidence) is ChainEvidence
        and "chain_signature" in meta_values
        and _sequence_evidence_available(meta_values["chain_signature"])
    )
    behavior_available = (
        _sequence_evidence_available(tags)
        and "behavior_signature" in meta_values
        and _sequence_evidence_available(meta_values["behavior_signature"])
    )
    tagset = cluster_text_set(tags, reason="cluster_tag_input_unavailable")
    chains = (
        cluster_chain_signature(chain_evidence)
        if type(chain_evidence) is ChainEvidence else set()
    )
    behaviors = cluster_behavior_signature(tagset)
    tag_reference = cluster_text_set(
        microcluster_value(meta, "tag_signature", ()),
        reason="cluster_tag_signature_unavailable",
    )
    chain_reference = cluster_text_set(
        microcluster_value(meta, "chain_signature", ()),
        reason="cluster_chain_signature_unavailable",
    )
    behavior_reference = cluster_text_set(
        microcluster_value(meta, "behavior_signature", ()),
        reason="cluster_behavior_signature_unavailable",
    )
    tag_score = cluster_jaccard_similarity(tagset, tag_reference)
    chain_score = cluster_jaccard_similarity(chains, chain_reference)
    behavior_score = cluster_jaccard_similarity(behaviors, behavior_reference)
    components: list[tuple[float, float]] = []
    available_weight = 0.0
    for score, weight, available in (
        (cosine, policy.cosine_weight, cosine_available),
        (mahalanobis, policy.mahalanobis_weight, mahalanobis_available),
    ):
        if available:
            components.append((score, weight))
            available_weight += weight
    for left, right, score, weight, available in (
        (tagset, tag_reference, tag_score, policy.tag_weight, tag_available),
        (chains, chain_reference, chain_score, policy.chain_weight, chain_available),
        (
            behaviors,
            behavior_reference,
            behavior_score,
            policy.behavior_weight,
            behavior_available,
        ),
    ):
        if available:
            available_weight += weight
        if available and (left or right):
            components.append((score, weight))
    used_weight = sum(weight for _score, weight in components)
    combined = (
        sum(score * weight for score, weight in components) / used_weight
        if used_weight > 0.0 else 0.0
    )
    full_weight = sum((
        policy.cosine_weight,
        policy.mahalanobis_weight,
        policy.tag_weight,
        policy.chain_weight,
        policy.behavior_weight,
    ))
    coverage = min(1.0, available_weight / max(full_weight, 1e-9))
    support = nonnegative_microcluster_int(
        microcluster_value(meta, "trusted_sample_count", 0),
    )
    support_confidence = min(1.0, support / float(policy.minimum_trusted_support))
    published_confidence = max(0.0, min(1.0, finite_cluster_metric(
        microcluster_value(meta, "confidence", 0.0), 0.0,
    )))
    support_factor = 0.85 + 0.10 * support_confidence + 0.05 * published_confidence
    coverage_factor = 0.70 + 0.30 * coverage
    if microcluster_value(meta, "drift_alarm", False) is True:
        support_factor *= 0.25
    score = max(0.0, min(1.0, combined * support_factor * coverage_factor))
    return ClusterSimilarityEvidence(
        score, cosine, mahalanobis, tag_score, chain_score, behavior_score,
        coverage, support_confidence, diagonal_distance,
    )


def cluster_similarity(
    feature_vector: object,
    centroid: object,
    chain_evidence: ChainEvidence,
    tags: object = None,
    meta: object = None,
    node: object = None,
    *,
    policy: ClusterPolicyManifest = CLUSTER_POLICY,
) -> float:
    return cluster_similarity_evidence(
        feature_vector,
        centroid,
        chain_evidence,
        tags=tags,
        meta=meta,
        node=node,
        policy=policy,
    ).score


__all__ = (
    "ClusterSimilarityEvidence",
    "cluster_jaccard_similarity",
    "cluster_similarity",
    "cluster_similarity_evidence",
)
