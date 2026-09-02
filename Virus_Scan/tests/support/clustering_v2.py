"""Canonical Stage2636.04 clustering fixtures for current-schema tests."""
from __future__ import annotations

from collections.abc import Iterable
import hashlib
from typing import Final

from Virus_Scan.models.clustering.feature_registry import (
    ASSIGNMENT_FEATURE_COUNT,
    RAW_FEATURE_COUNT,
)
from Virus_Scan.models.clustering.microcluster import (
    QUARANTINED,
    TRUSTED_BENIGN,
    TRUSTED_MALICIOUS,
    commit_microcluster_snapshot,
    empty_microcluster_snapshot,
    microcluster_with_fields,
)
from Virus_Scan.models.clustering.normalization import normalize_cluster_vector
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, cluster_state, configure_runtime_cluster_state, runtime_cluster_state_to_json
from Virus_Scan.models.contracts.learning_authority import (
    LEARNING_AUTHORITY_PROFILE_GATE,
    LEARNING_DISPOSITION_ACCEPTED,
    LearningDecision,
    make_replay_key,
)
from Virus_Scan.models.profiles.learning_decision import (
    build_external_malicious_clustering_decision,
)

RAW_CLUSTER_DIMENSIONS: Final[int] = RAW_FEATURE_COUNT
ASSIGNMENT_CLUSTER_DIMENSIONS: Final[int] = ASSIGNMENT_FEATURE_COUNT



def clustering_learning_decision(
    observation_id: str,
    *,
    verdict: str = "clean",
    ordinal: int = 1,
    engine: str = "unity",
) -> LearningDecision:
    """Build one exact provenance-bound clustering authorization for tests."""
    digest = hashlib.sha256(observation_id.encode("utf-8")).hexdigest()
    context_identity = (("learning_baseline_key", engine + "/.test"),)
    if verdict in {"malicious", "confirmed_malicious"}:
        return build_external_malicious_clustering_decision(
            observation_id=observation_id,
            observation_digest_value=digest,
            engine=engine,
            context_identity=context_identity,
            label_source="stage2636_test_fixture",
            decision_ordinal=max(0, ordinal),
            verdict=verdict,
            risk=1.0,
        )
    replay_key = make_replay_key(
        observation_id=observation_id,
        observation_digest=digest,
        engine=engine,
        context_identity=context_identity,
        verdict=verdict,
        risk=0.0,
        scan_integrity_state="complete",
        dangerous_anchor_hits=(),
        triage_block_hits=(),
        disposition=LEARNING_DISPOSITION_ACCEPTED,
        permitted_model_targets=("clustering",),
        authority=LEARNING_AUTHORITY_PROFILE_GATE,
        reason="test_authorized_clustering_learning",
        gate_version="test_cluster_gate_v3",
        decision_ordinal=max(0, ordinal),
    )
    decision = LearningDecision(
        observation_id=observation_id,
        observation_digest=digest,
        engine=engine,
        context_identity=context_identity,
        verdict=verdict,
        risk=0.0,
        scan_integrity_state="complete",
        dangerous_anchor_hits=(),
        triage_block_hits=(),
        disposition=LEARNING_DISPOSITION_ACCEPTED,
        permitted_model_targets=("clustering",),
        authority=LEARNING_AUTHORITY_PROFILE_GATE,
        reason="test_authorized_clustering_learning",
        gate_version="test_cluster_gate_v3",
        decision_ordinal=max(0, ordinal),
        replay_key=replay_key,
    )
    decision.validate()
    return decision

def raw_cluster_vector(*, offset: float = 0.0) -> list[float]:
    """Return one valid, deterministic raw vector in registry order."""
    values = [
        4.0 + offset,
        1.0,
        3.0 + offset,
        0.7,
        0.4,
        0.6,
        0.5,
        0.3,
        0.2,
        1.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
    ]
    assert len(values) == RAW_CLUSTER_DIMENSIONS
    return values


def assignment_cluster_vector(*, offset: float = 0.0) -> list[float]:
    normalized = normalize_cluster_vector(raw_cluster_vector(offset=offset))
    if not normalized.available:
        raise AssertionError(normalized.unavailable_reason)
    return list(normalized.assignment_vector)


def canonical_microcluster_snapshot(
    cluster_id: str,
    *,
    members: Iterable[str] = (),
    kind: str = "mixed",
    tags: Iterable[str] = (),
    chains: Iterable[str] = (),
    behaviors: Iterable[str] = (),
    raw_vector: object = None,
    centroid_vector: Iterable[float] | None = None,
    confidence: float = 0.8,
    malicious_ratio: float | None = None,
    benign_ratio: float | None = None,
    trusted_sample_count: int = 3,
    quarantined_sample_count: int = 0,
    created_ordinal: int = 1,
    updated_ordinal: int = 3,
    influence_enabled: bool = True,
    context_key: str = "test_context",
) -> object:
    """Build one complete immutable current-schema microcluster snapshot."""
    member_tuple = tuple(sorted(str(member).strip() for member in members if str(member).strip()))
    seed_node = member_tuple[0] if member_tuple else "fixture-node"
    vector_input = raw_cluster_vector() if raw_vector is None else raw_vector
    normalized = normalize_cluster_vector(vector_input)
    if not normalized.available:
        raise AssertionError(normalized.unavailable_reason)
    authority = (
        TRUSTED_MALICIOUS if kind == "malicious"
        else TRUSTED_BENIGN if kind == "benign"
        else QUARANTINED
    )
    snapshot = empty_microcluster_snapshot(
        cluster_id,
        context_key,
        normalized,
        node=seed_node,
        observation_digest="fixture-observation-1",
        authority=authority,
        observed_kind=kind,
        tags=tuple(tags),
        chains=tuple(chains),
        behaviors=tuple(behaviors),
        ordinal=max(1, created_ordinal),
    )
    centroid = tuple(normalized.assignment_vector if centroid_vector is None else centroid_vector)
    if len(centroid) != ASSIGNMENT_CLUSTER_DIMENSIONS:
        raise AssertionError("fixture centroid must use current assignment dimensions")
    trusted = max(0, int(trusted_sample_count))
    quarantined = max(0, int(quarantined_sample_count))
    if malicious_ratio is None:
        malicious_ratio = 1.0 if kind == "malicious" else 0.0 if kind == "benign" else 0.5
    if benign_ratio is None:
        benign_ratio = 1.0 if kind == "benign" else 0.0 if kind == "malicious" else 0.5
    malicious_samples = round(trusted * malicious_ratio)
    benign_samples = max(0, trusted - malicious_samples)
    tag_tuple = tuple(sorted({str(value).strip().lower() for value in tags if str(value).strip()}))
    chain_tuple = tuple(sorted({str(value).strip().lower() for value in chains if str(value).strip()}))
    behavior_tuple = tuple(sorted({str(value).strip().lower() for value in behaviors if str(value).strip()}))
    return microcluster_with_fields(
        snapshot,
        members=frozenset(member_tuple),
        kind=kind,
        centroid_vector=centroid,
        dimension_mean=centroid,
        dimension_variance=tuple(0.05 for _ in centroid),
        dimension_count=tuple(trusted for _ in centroid),
        trusted_sample_count=trusted,
        quarantined_sample_count=quarantined,
        samples=trusted + quarantined,
        malicious_samples=malicious_samples,
        benign_samples=benign_samples,
        malicious_ratio=float(malicious_ratio),
        benign_ratio=float(benign_ratio),
        label_support=(("benign", benign_samples), ("malicious", malicious_samples)),
        tag_signature=frozenset(tag_tuple),
        chain_signature=frozenset(chain_tuple),
        behavior_signature=frozenset(behavior_tuple),
        tag_signature_counts=tuple((value, trusted) for value in tag_tuple),
        chain_signature_counts=tuple((value, trusted) for value in chain_tuple),
        behavior_signature_counts=tuple((value, trusted) for value in behavior_tuple),
        confidence=float(confidence),
        influence_enabled=bool(influence_enabled),
        created_ordinal=max(0, int(created_ordinal)),
        updated_ordinal=max(0, int(updated_ordinal)),
        created=float(max(0, int(created_ordinal))),
        last_updated=float(max(0, int(updated_ordinal))),
        last_known_good_centroid=centroid,
        observation_digests=tuple(f"fixture-observation-{index}" for index in range(1, trusted + quarantined + 1)),
    )


def seed_canonical_microcluster(
    state: RuntimeClusterState,
    cluster_id: str,
    *,
    members: Iterable[str] = (),
    node_vectors: dict[str, Iterable[float]] | None = None,
    **kwargs: object,
) -> object:
    """Commit one current-schema snapshot and its node indexes to bound state."""
    member_tuple = tuple(sorted(str(member).strip() for member in members if str(member).strip()))
    snapshot = canonical_microcluster_snapshot(cluster_id, members=member_tuple, **kwargs)
    commit_microcluster_snapshot(cluster_id, snapshot)
    centroid = list(snapshot["centroid_vector"])
    for member in member_tuple:
        state.node_cluster_map[member] = cluster_id
        vector = centroid if node_vectors is None else list(node_vectors.get(member, centroid))
        state.node_feature_vectors[member] = list(vector)
    return snapshot



def canonical_cluster_state_payload(
    cluster_id: str = "fixture-cluster",
    *,
    members: Iterable[str] = ("fixture-node",),
    **kwargs: object,
) -> dict[str, object]:
    """Serialize one isolated canonical cluster state and restore prior binding."""
    try:
        previous = cluster_state()
    except RuntimeError:
        previous = None
    source = RuntimeClusterState()
    configure_runtime_cluster_state(source)
    seed_canonical_microcluster(source, cluster_id, members=members, **kwargs)
    payload = runtime_cluster_state_to_json()
    if previous is not None:
        configure_runtime_cluster_state(previous)
    return payload

def current_cluster_state_json() -> dict[str, object]:
    """Return the current canonical persisted shape for the bound runtime state."""
    return runtime_cluster_state_to_json()


__all__ = (
    "ASSIGNMENT_CLUSTER_DIMENSIONS",
    "RAW_CLUSTER_DIMENSIONS",
    "assignment_cluster_vector",
    "canonical_cluster_state_payload",
    "canonical_microcluster_snapshot",
    "clustering_learning_decision",
    "current_cluster_state_json",
    "raw_cluster_vector",
    "seed_canonical_microcluster",
)
