"""Stage2636.04 canonical clustering architecture regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence

from dataclasses import replace
from types import MappingProxyType

import pytest

from Virus_Scan.models import clustering
from Virus_Scan.models.clustering.assignment_decision import deterministic_cluster_id
from Virus_Scan.models.clustering.feature_registry import (
    ASSIGNMENT_FEATURE_COUNT,
    ASSIGNMENT_FEATURE_NAMES,
    CLUSTER_FEATURE_REGISTRY,
    RAW_FEATURE_COUNT,
    VECTOR_FEATURE_NAMES,
)
from Virus_Scan.models.clustering.microcluster_values import freeze_microcluster_snapshot
from Virus_Scan.models.clustering.microcluster import commit_microcluster_snapshot
from Virus_Scan.models.clustering.microcluster import (
    QUARANTINED,
    TRUSTED_BENIGN,
    empty_microcluster_snapshot,
)
from Virus_Scan.models.clustering.microcluster_update import update_microcluster_snapshot
from Virus_Scan.models.clustering.normalization import normalize_cluster_vector
from Virus_Scan.models.clustering.policy import CLUSTER_POLICY
from Virus_Scan.runtime.cluster_state import (
    CLUSTER_STATE_MAX_CLUSTERS,
    CLUSTER_STATE_MAX_LEARNING_KEYS,
    CLUSTER_STATE_MAX_NODE_ASSIGNMENTS,
    RuntimeClusterState,
    configure_runtime_cluster_state,
    runtime_cluster_state_to_json,
)
from Virus_Scan.tests.support.clustering_v2 import (
    canonical_microcluster_snapshot,
    clustering_learning_decision,
    raw_cluster_vector,
)


class _HostileSchemaVersion:
    def __init__(self) -> None:
        self.str_calls = 0
        self.eq_calls = 0

    def __str__(self) -> str:
        self.str_calls += 1
        raise AssertionError("schema conversion hook executed")

    def __eq__(self, other: object) -> bool:
        del other
        self.eq_calls += 1
        raise AssertionError("schema equality hook executed")


def _bind_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def test_stage2636_04_snapshot_freeze_is_recursive_and_exact_builtin_only() -> None:
    snapshot = freeze_microcluster_snapshot({
        "cluster_id": "cluster-a",
        "nested": {"rows": [{"score": 1.0}]},
    })

    assert type(snapshot) is type(MappingProxyType({}))
    assert type(snapshot["nested"]) is type(MappingProxyType({}))
    assert type(snapshot["nested"]["rows"]) is tuple
    assert type(snapshot["nested"]["rows"][0]) is type(MappingProxyType({}))
    with pytest.raises(TypeError):
        snapshot["nested"]["rows"][0]["score"] = 2.0
    with pytest.raises(ValueError, match="microcluster_snapshot_value_invalid"):
        freeze_microcluster_snapshot({"unsafe": object()})


def test_stage2636_04_schema_rejection_executes_no_caller_hooks() -> None:
    hostile = _HostileSchemaVersion()

    normalized = normalize_cluster_vector(
        raw_cluster_vector(), feature_schema_version=hostile,
    )

    assert normalized.available is False
    assert normalized.unavailable_reason == "cluster_feature_schema_version_mismatch"
    assert normalized.feature_schema_version == ""
    assert hostile.str_calls == 0
    assert hostile.eq_calls == 0


def test_stage2636_04_registry_owns_raw_and_assignment_dimensions() -> None:
    assert RAW_FEATURE_COUNT == len(CLUSTER_FEATURE_REGISTRY) == len(VECTOR_FEATURE_NAMES)
    assert ASSIGNMENT_FEATURE_COUNT == len(ASSIGNMENT_FEATURE_NAMES)

    baseline = raw_cluster_vector()
    altered_feedback = list(baseline)
    altered_feedback[-3:] = [1.0, 1.0, 1.0]
    normalized_baseline = normalize_cluster_vector(baseline)
    normalized_feedback = normalize_cluster_vector(altered_feedback)

    assert normalized_baseline.available is True
    assert normalized_feedback.available is True
    assert len(normalized_baseline.assignment_vector) == ASSIGNMENT_FEATURE_COUNT
    assert normalized_baseline.assignment_vector == normalized_feedback.assignment_vector


def test_stage2636_04_vector_producer_uses_registry_order() -> None:
    _bind_state()
    vector = clustering.build_feature_vector(
        "node-a",
        tags=("tag-a",),
        graph_features={"risk": 0.25, "anomaly": 0.5},
        temporal_features={"belief": 0.75},
        markov_features={"transition": 0.4, "rarity": 0.3, "pair_anomaly": 0.2},
        engine_context={"unity": 1.0},
    )
    by_name = dict(zip(VECTOR_FEATURE_NAMES, vector, strict=True))

    assert len(vector) == RAW_FEATURE_COUNT
    assert by_name["graph_risk"] == 0.25
    assert by_name["temporal_belief"] == 0.75
    assert by_name["unity_context"] == 1.0


def test_stage2636_04_cluster_identity_includes_canonical_signatures() -> None:
    _bind_state()
    normalized = normalize_cluster_vector(raw_cluster_vector())

    left = deterministic_cluster_id(
        "unity_exe_cluster_", normalized, "malicious", ("tag:alpha",),
    )
    right = deterministic_cluster_id(
        "unity_exe_cluster_", normalized, "malicious", ("tag:beta",),
    )

    assert left != right
    assert left == deterministic_cluster_id(
        "unity_exe_cluster_", normalized, "malicious", ("tag:alpha",),
    )


def test_stage2636_04_trusted_label_provenance_is_replay_key_bound() -> None:
    state = _bind_state()
    decision = clustering_learning_decision("stage2636-provenance", ordinal=7)

    cluster_id = clustering.assign_cluster_with_context_tags(
        "node-a",
        raw_cluster_vector(),
        tags=physical_tag_evidence(("image_asset",)),
        engine_context={"unity": 1.0},
        learning_decision=decision,
    )

    snapshot = state.cluster_metadata[cluster_id]
    assert snapshot["label_provenance"] == (
        f"learning_decision_v1:{decision.replay_key}",
    )


def test_stage2636_04_runtime_serialization_uses_policy_cluster_bound() -> None:
    state = _bind_state()
    for index in range(CLUSTER_POLICY.maximum_cluster_count + 1):
        state.cluster_metadata[f"cluster-{index:04d}"] = {
            "confidence": 0.0,
            "malicious_ratio": 0.0,
            "samples": 0,
            "last_updated": 0.0,
        }

    serialized = runtime_cluster_state_to_json()

    assert len(serialized["microclusters"]) == CLUSTER_POLICY.maximum_cluster_count


def test_stage2636_04_runtime_and_model_publish_one_resource_policy() -> None:
    assert CLUSTER_POLICY.maximum_cluster_count == CLUSTER_STATE_MAX_CLUSTERS
    assert CLUSTER_POLICY.maximum_node_assignments == CLUSTER_STATE_MAX_NODE_ASSIGNMENTS
    assert CLUSTER_POLICY.maximum_learning_keys == CLUSTER_STATE_MAX_LEARNING_KEYS


def test_stage2636_04_snapshot_builders_reject_forged_or_corrupt_inputs() -> None:
    normalized = normalize_cluster_vector(raw_cluster_vector())
    forged = replace(normalized, vector_digest="0" * 64)

    with pytest.raises(ValueError, match="cluster_normalized_vector_digest_mismatch"):
        empty_microcluster_snapshot(
            "cluster-forged", "test-context", forged, node="node-a",
            observation_digest="digest-a", authority=TRUSTED_BENIGN,
            observed_kind="benign", tags=(), chains=(), behaviors=(), ordinal=1,
        )

    corrupt = dict(canonical_microcluster_snapshot("cluster-corrupt", kind="benign"))
    corrupt["confidence"] = "trusted"
    with pytest.raises(ValueError, match="confidence_invalid"):
        update_microcluster_snapshot(
            freeze_microcluster_snapshot(corrupt), normalized, node="node-b",
            observation_digest="digest-b", authority=TRUSTED_BENIGN,
            observed_kind="benign", tags=(), chains=(), behaviors=(),
            ordinal=2, assignment_similarity=1.0,
        )

    with pytest.raises(ValueError, match="created_ordinal_invalid"):
        empty_microcluster_snapshot(
            "cluster-negative-ordinal", "test-context", normalized, node="node-c",
            observation_digest="digest-c", authority=TRUSTED_BENIGN,
            observed_kind="benign", tags=(), chains=(), behaviors=(), ordinal=-1,
        )


def test_stage2636_04_commit_rejects_noncanonical_snapshot_atomically() -> None:
    state = _bind_state()
    valid = dict(canonical_microcluster_snapshot("cluster-valid"))
    valid["centroid_vector"] = valid["centroid_vector"][:-1]
    invalid = freeze_microcluster_snapshot(valid)

    with pytest.raises(ValueError, match="centroid_vector_dimension_mismatch"):
        commit_microcluster_snapshot("cluster-valid", invalid)

    assert state.cluster_metadata == {}
    assert state.cluster_signatures == {}
    assert state.benign_clusters == {}
    assert state.malicious_clusters == {}
    assert state.mixed_clusters == {}


@pytest.mark.parametrize(
    ("field_name", "field_value", "error"),
    (
        ("confidence", "high", "confidence_invalid"),
        ("tag_signature", ("valid", 3), "tag_signature_invalid"),
        ("tag_signature_counts", (("tag", -1),), "tag_signature_counts_invalid"),
        ("drift_alarm", 1, "drift_alarm_invalid"),
        (
            "normalization_support_counts",
            tuple(1 for _ in range(ASSIGNMENT_FEATURE_COUNT)),
            "normalization_support_manifest_mismatch",
        ),
        (
            "normalization_transform_ids",
            tuple("bounded_unit" for _ in range(ASSIGNMENT_FEATURE_COUNT)),
            "normalization_transform_manifest_mismatch",
        ),
        ("normalization_vector_digest", "bad", "normalization_vector_digest_invalid"),
        ("last_update_authority", "trusted", "last_update_authority_invalid"),
        ("created_source", "wall_clock", "created_source_invalid"),
        (
            "dimension_variance",
            (-0.1, *tuple(0.0 for _ in range(ASSIGNMENT_FEATURE_COUNT - 1))),
            "dimension_variance_range_invalid",
        ),
        (
            "last_assignment_evidence",
            (("score", float("nan")),),
            "last_assignment_evidence_value_nonfinite",
        ),
    ),
)
def test_stage2636_04_commit_rejects_malformed_optional_fields_atomically(
    field_name: str, field_value: object, error: str,
) -> None:
    state = _bind_state()
    values = dict(canonical_microcluster_snapshot("cluster-optional-invalid"))
    values[field_name] = field_value

    with pytest.raises(ValueError, match=error):
        commit_microcluster_snapshot(
            "cluster-optional-invalid", freeze_microcluster_snapshot(values),
        )

    assert state.cluster_metadata == {}
    assert state.cluster_signatures == {}
    assert state.benign_clusters == {}
    assert state.malicious_clusters == {}
    assert state.mixed_clusters == {}


def test_stage2636_04_count_normalization_is_robust_monotonic_and_bounded() -> None:
    low = raw_cluster_vector(); low[0] = 0.0
    middle = raw_cluster_vector(); middle[0] = 25.0
    high = raw_cluster_vector(); high[0] = 10_000.0

    low_value = normalize_cluster_vector(low).assignment_vector[0]
    middle_value = normalize_cluster_vector(middle).assignment_vector[0]
    high_value = normalize_cluster_vector(high).assignment_vector[0]

    assert -1.0 <= low_value < middle_value < high_value <= 1.0


def test_stage2636_04_quarantine_and_outlier_never_move_trusted_centroid() -> None:
    normalized = normalize_cluster_vector(raw_cluster_vector())
    trusted = empty_microcluster_snapshot(
        "cluster-trusted",
        "test-context",
        normalized,
        node="trusted-node",
        observation_digest="trusted-digest",
        authority=TRUSTED_BENIGN,
        observed_kind="benign",
        tags=("image_asset",),
        chains=(),
        behaviors=("image_asset",),
        ordinal=1,
        label_provenance=("learning_decision_v1:" + "a" * 64,),
    )
    centroid = trusted["centroid_vector"]
    poison_raw = raw_cluster_vector(); poison_raw[5] = 1.0; poison_raw[6] = 1.0
    poison = normalize_cluster_vector(poison_raw)

    quarantined = update_microcluster_snapshot(
        trusted,
        poison,
        node="unknown-node",
        observation_digest="unknown-digest",
        authority=QUARANTINED,
        observed_kind="mixed",
        tags=("novel_behavior",),
        chains=(),
        behaviors=("novel_behavior",),
        ordinal=2,
        assignment_similarity=0.9,
    )
    outlier = update_microcluster_snapshot(
        quarantined,
        poison,
        node="outlier-node",
        observation_digest="outlier-digest",
        authority=TRUSTED_BENIGN,
        observed_kind="benign",
        tags=("image_asset",),
        chains=(),
        behaviors=("image_asset",),
        ordinal=3,
        assignment_similarity=0.0,
    )

    assert quarantined["centroid_vector"] == centroid
    assert quarantined["last_update_applied"] is False
    assert outlier["centroid_vector"] == centroid
    assert outlier["last_update_applied"] is False
    assert outlier["last_update_rejected_reason"] == "outlier_update_gate"


def test_stage2636_04_quarantine_signatures_cannot_poison_trusted_empty_signatures() -> None:
    normalized = normalize_cluster_vector(raw_cluster_vector())
    trusted = empty_microcluster_snapshot(
        "cluster-empty-trusted", "test-context", normalized, node="trusted-node",
        observation_digest="trusted-digest", authority=TRUSTED_BENIGN,
        observed_kind="benign", tags=(), chains=(), behaviors=(), ordinal=1,
    )
    quarantined = update_microcluster_snapshot(
        trusted, normalized, node="unknown-node", observation_digest="unknown-digest",
        authority=QUARANTINED, observed_kind="mixed", tags=("poison-tag",),
        chains=("poison-chain",), behaviors=("poison-behavior",), ordinal=2,
        assignment_similarity=1.0,
    )

    assert quarantined["tag_signature"] == frozenset()
    assert quarantined["chain_signature"] == frozenset()
    assert quarantined["behavior_signature"] == frozenset()
    assert quarantined["quarantine_tag_counts"] == (("poison-tag", 1),)
    assert quarantined["quarantine_chain_counts"] == (("poison-chain", 1),)
    assert quarantined["quarantine_behavior_counts"] == (("poison-behavior", 1),)

    observational = empty_microcluster_snapshot(
        "cluster-observational", "test-context", normalized, node="unknown-only",
        observation_digest="unknown-only-digest", authority=QUARANTINED,
        observed_kind="mixed", tags=("observational-tag",), chains=(),
        behaviors=("observational-behavior",), ordinal=1,
    )
    assert observational["tag_signature"] == frozenset(("observational-tag",))
    assert observational["behavior_signature"] == frozenset(("observational-behavior",))


def test_stage2636_04_duplicate_observation_is_idempotent_and_replay_deterministic() -> None:
    def run_once() -> dict[str, object]:
        state = _bind_state()
        decision = clustering_learning_decision("stage2636-idempotent", ordinal=11)
        first = clustering.assign_cluster_with_context_tags(
            "node-idempotent",
            raw_cluster_vector(),
            tags=physical_tag_evidence(("image_asset",)),
            engine_context={"media": 1.0},
            learning_decision=decision,
        )
        samples = state.cluster_metadata[first]["samples"]
        second = clustering.assign_cluster_with_context_tags(
            "node-idempotent",
            raw_cluster_vector(),
            tags=physical_tag_evidence(("image_asset",)),
            engine_context={"media": 1.0},
            learning_decision=decision,
        )
        assert first == second
        assert state.cluster_metadata[first]["samples"] == samples
        return runtime_cluster_state_to_json()

    assert run_once() == run_once()


class _RecordingClusterStore(dict[str, set[str]]):
    def __init__(self) -> None:
        super().__init__()
        self.writes: list[str] = []

    def __setitem__(self, key: str, value: set[str]) -> None:
        self.writes.append(key)
        super().__setitem__(key, value)


def test_stage2636_04_benign_assignment_never_enters_malicious_store_temporarily() -> None:
    state = _bind_state()
    recording = _RecordingClusterStore()
    state.malicious_clusters = recording
    decision = clustering_learning_decision("stage2636-benign-store", ordinal=12)

    cluster_id = clustering.assign_cluster_with_context_tags(
        "image.png",
        raw_cluster_vector(),
        tags=physical_tag_evidence(("image_asset",)),
        engine_context={"media": 1.0},
        learning_decision=decision,
    )

    assert cluster_id in state.benign_clusters
    assert recording.writes == []

class _HostileSupportValue:
    def __init__(self) -> None:
        self.touched = 0

    def __bool__(self) -> bool:  # pragma: no cover - must never execute
        self.touched += 1
        raise AssertionError("support truthiness hook executed")

    def __int__(self) -> int:  # pragma: no cover - must never execute
        self.touched += 1
        raise AssertionError("support integer hook executed")


def test_stage2636_04_similarity_rejects_unavailable_components_without_hooks() -> None:
    from Virus_Scan.models.clustering.similarity import cluster_similarity_evidence

    normalized = normalize_cluster_vector(raw_cluster_vector())
    snapshot = canonical_microcluster_snapshot(
        "strict-similarity", members=("node-a",), kind="benign",
        tags=("image_asset",), behaviors=("image_asset",),
    )
    hostile = _HostileSupportValue()
    malformed = dict(snapshot)
    malformed["trusted_sample_count"] = hostile

    evidence = cluster_similarity_evidence(
        normalized.assignment_vector,
        snapshot["centroid_vector"],
        object(),
        tags=physical_tag_evidence(("image_asset",)),
        meta=malformed,
    )

    assert evidence.chain_jaccard == 0.0
    assert evidence.component_coverage < 1.0
    assert evidence.support_confidence == 0.0
    assert 0.0 <= evidence.score < 1.0
    assert hostile.touched == 0


def test_stage2636_04_corrupt_node_vector_cannot_publish_positive_anomaly() -> None:
    from Virus_Scan.models.clustering.anomaly import cluster_anomaly_boost_evidence
    from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster

    state = _bind_state()
    seed_canonical_microcluster(
        state,
        "strict-vector-cluster",
        members=("strict-node",),
        kind="benign",
        tags=("image_asset",),
        trusted_sample_count=3,
        influence_enabled=True,
    )
    state.node_feature_vectors["strict-node"] = [1.0]

    evidence = cluster_anomaly_boost_evidence("strict-node")

    assert evidence["cluster_anomaly_boost"] == 0.0
    assert evidence["cluster_anomaly_ready"] is False
    assert evidence["cluster_unavailable_reason"] == "cluster_vector_unavailable"


def test_stage2636_04_runtime_serialization_does_not_normalize_corrupt_vectors() -> None:
    state = _bind_state()
    state.cluster_metadata["corrupt-vector-cluster"] = canonical_microcluster_snapshot(
        "corrupt-vector-cluster", members=("corrupt-node",), kind="benign",
    )
    state.node_cluster_map["corrupt-node"] = "corrupt-vector-cluster"
    state.node_feature_vectors["corrupt-node"] = [1.0, object()]

    payload = runtime_cluster_state_to_json()

    assert payload["node_feature_vectors"]["corrupt-node"] == []
