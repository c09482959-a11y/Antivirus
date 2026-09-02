"""Immutable clustering policy selected by Stage2636.04 holdout evaluation."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Final

from Virus_Scan.runtime.cluster_state import (
    CLUSTER_STATE_MAX_CLUSTERS,
    CLUSTER_STATE_MAX_LEARNING_KEYS,
    CLUSTER_STATE_MAX_NODE_ASSIGNMENTS,
    CLUSTER_STATE_SCHEMA_VERSION,
)

CLUSTER_POLICY_VERSION: Final[str] = "cluster_policy_stage2636_04_v4"
CLUSTER_SIMILARITY_VERSION: Final[str] = "cluster_hybrid_similarity_v3"
CLUSTER_MODEL_VERSION: Final[str] = "online_microcluster_v2"


@dataclass(frozen=True, slots=True)
class ClusterPolicyManifest:
    cosine_weight: float
    mahalanobis_weight: float
    tag_weight: float
    chain_weight: float
    behavior_weight: float
    benign_reuse_threshold: float
    malicious_reuse_threshold: float
    quarantine_reuse_threshold: float
    trusted_update_similarity_gate: float
    maximum_diagonal_distance: float
    maximum_radius: float
    maximum_update_influence: float
    minimum_trusted_support: int
    maximum_signature_terms: int
    maximum_observation_digests: int
    maximum_members: int
    maximum_quarantined_samples: int
    maximum_cluster_count: int
    maximum_node_assignments: int
    maximum_learning_keys: int
    version: str = CLUSTER_POLICY_VERSION
    similarity_version: str = CLUSTER_SIMILARITY_VERSION
    selection_evidence: str = "stage2636_04_family_source_validation_v1"


CLUSTER_POLICY: Final[ClusterPolicyManifest] = ClusterPolicyManifest(
    cosine_weight=0.18,
    mahalanobis_weight=0.16,
    tag_weight=0.24,
    chain_weight=0.30,
    behavior_weight=0.12,
    benign_reuse_threshold=0.84,
    malicious_reuse_threshold=0.76,
    quarantine_reuse_threshold=0.82,
    trusted_update_similarity_gate=0.72,
    maximum_diagonal_distance=3.5,
    maximum_radius=0.85,
    maximum_update_influence=0.50,
    minimum_trusted_support=3,
    maximum_signature_terms=256,
    maximum_observation_digests=512,
    maximum_members=2048,
    maximum_quarantined_samples=4096,
    maximum_cluster_count=CLUSTER_STATE_MAX_CLUSTERS,
    maximum_node_assignments=CLUSTER_STATE_MAX_NODE_ASSIGNMENTS,
    maximum_learning_keys=CLUSTER_STATE_MAX_LEARNING_KEYS,
)


def _policy_payload() -> dict[str, object]:
    return {
        field_name: getattr(CLUSTER_POLICY, field_name)
        for field_name in CLUSTER_POLICY.__dataclass_fields__
    }


CLUSTER_POLICY_DIGEST: Final[str] = hashlib.sha256(
    json.dumps(_policy_payload(), sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
).hexdigest()


__all__ = (
    "CLUSTER_MODEL_VERSION",
    "CLUSTER_POLICY",
    "CLUSTER_POLICY_DIGEST",
    "CLUSTER_POLICY_VERSION",
    "CLUSTER_SIMILARITY_VERSION",
    "CLUSTER_STATE_SCHEMA_VERSION",
    "ClusterPolicyManifest",
)
