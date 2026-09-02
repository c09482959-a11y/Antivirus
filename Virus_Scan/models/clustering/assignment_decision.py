"""Deterministic candidate scoring and assignment decision owner."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Final

from Virus_Scan.models.clustering.common import safe_cluster_text
from Virus_Scan.models.clustering.microcluster import (
    QUARANTINED,
    TRUSTED_BENIGN,
    TRUSTED_MALICIOUS,
)
from Virus_Scan.models.clustering.microcluster_values import (
    microcluster_mapping,
    microcluster_value,
)
from Virus_Scan.models.clustering.normalization import NormalizedClusterVector
from Virus_Scan.models.clustering.policy import (
    CLUSTER_POLICY,
    CLUSTER_POLICY_VERSION,
    CLUSTER_SIMILARITY_VERSION,
)
from Virus_Scan.models.clustering.similarity import (
    ClusterSimilarityEvidence,
    cluster_similarity_evidence,
)
from Virus_Scan.models.clustering.state import cluster_metadata
from Virus_Scan.models.contracts.learning_authority import (
    LEARNING_AUTHORITY_EXTERNAL_MALICIOUS,
    LEARNING_AUTHORITY_PROFILE_GATE,
)

_CLEAN_VERDICTS: Final[frozenset[str]] = frozenset({"benign", "clean", "benign_clean", "ok"})
_MALICIOUS_VERDICTS: Final[frozenset[str]] = frozenset({"malicious", "confirmed_malicious"})


@dataclass(frozen=True, slots=True)
class ClusterAssignmentDecision:
    cluster_id: str
    score: float
    threshold: float
    created: bool
    evidence: tuple[tuple[str, object], ...]


@dataclass(frozen=True, slots=True)
class ClusterUpdateDecision:
    authority: str
    allowed: bool
    reason: str


def observation_update_authority(
    learning_decision: object,
    observed_kind: str,
) -> ClusterUpdateDecision:
    """Derive update authority only from validated decision provenance."""
    verdict = safe_cluster_text(
        getattr(learning_decision, "verdict", ""), default_text="",
    ).lower()
    decision_authority = safe_cluster_text(
        getattr(learning_decision, "authority", ""), default_text="",
    ).lower()
    if (
        decision_authority == LEARNING_AUTHORITY_PROFILE_GATE
        and verdict in _CLEAN_VERDICTS
        and observed_kind == "benign"
    ):
        return ClusterUpdateDecision(TRUSTED_BENIGN, True, "trusted_clean_promotion")
    if (
        decision_authority == LEARNING_AUTHORITY_EXTERNAL_MALICIOUS
        and verdict in _MALICIOUS_VERDICTS
        and observed_kind == "malicious"
    ):
        return ClusterUpdateDecision(
            TRUSTED_MALICIOUS, True, "trusted_external_malicious_label",
        )
    if (
        decision_authority == LEARNING_AUTHORITY_PROFILE_GATE
        and verdict in _CLEAN_VERDICTS
        and observed_kind != "benign"
    ):
        return ClusterUpdateDecision(
            QUARANTINED, False, "clean_promotion_observation_conflict",
        )
    if decision_authority == LEARNING_AUTHORITY_EXTERNAL_MALICIOUS:
        return ClusterUpdateDecision(
            QUARANTINED, False, "external_malicious_label_observation_conflict",
        )
    return ClusterUpdateDecision(
        QUARANTINED, False, "observation_without_update_authority",
    )


def _threshold_for(authority: str) -> float:
    if authority == TRUSTED_BENIGN:
        return CLUSTER_POLICY.benign_reuse_threshold
    if authority == TRUSTED_MALICIOUS:
        return CLUSTER_POLICY.malicious_reuse_threshold
    return CLUSTER_POLICY.quarantine_reuse_threshold


def _candidate_is_eligible(snapshot: object, context_key: str, authority: str) -> bool:
    values = microcluster_mapping(snapshot)
    if not values or values.get("context_key") != context_key:
        return False
    if values.get("retention_state", "active") != "active":
        return False
    if values.get("drift_alarm") is True or values.get("purity_limit_exceeded") is True:
        return False
    existing_kind = safe_cluster_text(values.get("kind"), default_text="mixed")
    if authority == TRUSTED_BENIGN and existing_kind == "malicious":
        return False
    if authority == TRUSTED_MALICIOUS and existing_kind == "benign":
        return False
    return True


def _best_candidate(
    normalized: NormalizedClusterVector,
    context_key: str,
    authority: str,
    chain_evidence: object,
    signature_tags: object,
) -> tuple[str | None, ClusterSimilarityEvidence | None]:
    best_id: str | None = None
    best_evidence: ClusterSimilarityEvidence | None = None
    for raw_cluster_id, snapshot in sorted(
        tuple(cluster_metadata().items()), key=lambda item: safe_cluster_text(item[0]),
    ):
        cluster_id = safe_cluster_text(raw_cluster_id, default_text="")
        if cluster_id == "" or not _candidate_is_eligible(snapshot, context_key, authority):
            continue
        evidence = cluster_similarity_evidence(
            normalized.assignment_vector,
            microcluster_value(snapshot, "centroid_vector", ()),
            chain_evidence,
            tags=signature_tags,
            meta=snapshot,
        )
        if best_evidence is None or (
            evidence.score, cluster_id
        ) > (best_evidence.score, best_id or ""):
            best_id = cluster_id
            best_evidence = evidence
    return best_id, best_evidence


def deterministic_cluster_id(
    prefix: str,
    normalized: NormalizedClusterVector,
    observed_kind: str,
    signature_identity: object = (),
) -> str:
    if type(signature_identity) in (tuple, list, set, frozenset):
        signatures = tuple(sorted(
            item for item in signature_identity if type(item) is str and item != ""
        ))
    else:
        signatures = ()
    payload = json.dumps(
        {
            "context_key": prefix,
            "normalized_vector_digest": normalized.vector_digest,
            "observed_kind": observed_kind,
            "signature_identity": signatures,
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    identity = hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()[:12]
    base = f"{prefix}{identity}"
    ordinal = 1
    candidate = f"{base}_{ordinal}"
    while candidate in cluster_metadata():
        ordinal += 1
        candidate = f"{base}_{ordinal}"
    return candidate


def decide_cluster_assignment(
    normalized: NormalizedClusterVector,
    context_key: str,
    authority: str,
    observed_kind: str,
    chain_evidence: object,
    signature_tags: object,
    signature_identity: object = (),
) -> ClusterAssignmentDecision:
    threshold = _threshold_for(authority)
    best_id, best = _best_candidate(
        normalized, context_key, authority, chain_evidence, signature_tags,
    )
    if best_id is not None and best is not None and best.score >= threshold:
        return ClusterAssignmentDecision(
            best_id,
            best.score,
            threshold,
            False,
            (*best.as_pairs(), ("threshold", threshold), ("policy_version", CLUSTER_POLICY_VERSION)),
        )
    cluster_id = deterministic_cluster_id(
        context_key, normalized, observed_kind, signature_identity,
    )
    evidence: tuple[tuple[str, object], ...] = (
        ("score", best.score if best is not None else 0.0),
        ("threshold", threshold),
        ("candidate_cluster_id", best_id),
        ("decision", "new_cluster"),
        ("similarity_version", CLUSTER_SIMILARITY_VERSION),
        ("policy_version", CLUSTER_POLICY_VERSION),
    )
    return ClusterAssignmentDecision(
        cluster_id,
        best.score if best is not None else 0.0,
        threshold,
        True,
        evidence,
    )


__all__ = (
    "ClusterAssignmentDecision",
    "ClusterUpdateDecision",
    "decide_cluster_assignment",
    "deterministic_cluster_id",
    "observation_update_authority",
)
