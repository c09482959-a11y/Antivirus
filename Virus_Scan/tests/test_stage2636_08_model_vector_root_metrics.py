from __future__ import annotations
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence

from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import (
    chain_probability_component,
)
from Virus_Scan.detection.scoring.behavior.bucket_validation import (
    behavior_bucket_validation,
)
from Virus_Scan.detection.scoring.weighting.static_layer import (
    compute_quick_static_layer,
)
from Virus_Scan.detection.tags.heuristics.classifier_evidence import (
    ClassifierContribution,
    ClassifierEvidenceResult,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.models.clustering import VECTOR_FEATURE_NAMES as CLUSTER_VECTOR_FEATURE_NAMES
from Virus_Scan.models.clustering.vectors import build_feature_vector
from Virus_Scan.models.profiles.learning import (
    VECTOR_FEATURE_NAMES as PROFILE_VECTOR_FEATURE_NAMES,
    behavior_vector_from_scan,
)
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    graph_node_snapshot,
    reset_graph_state,
    update_graph_node_owned,
)


def _cluster_vector(tags: object) -> list[float]:
    configure_runtime_cluster_state(RuntimeClusterState())
    return build_feature_vector(
        "sample.bin",
        tags=tags,
        graph_features={},
        temporal_features={},
        markov_features={},
        engine_context={"other": 1.0},
    )


def test_stage2636_08_cluster_vector_counts_independent_roots_and_groups() -> None:
    one_root_aliases = physical_tag_evidence(("schtasks",), one_root=True)
    two_roots = physical_tag_evidence(("schtasks_create", "powershell_exec"))

    alias_vector = _cluster_vector(one_root_aliases)
    two_root_vector = _cluster_vector(two_roots)
    tag_count = CLUSTER_VECTOR_FEATURE_NAMES.index("tag_count")
    unique_tag_count = CLUSTER_VECTOR_FEATURE_NAMES.index("unique_tag_count")

    assert alias_vector[tag_count] == 1.0
    assert alias_vector[unique_tag_count] == 1.0
    assert two_root_vector[tag_count] == 2.0
    assert two_root_vector[unique_tag_count] == 2.0


def test_stage2636_08_profile_vector_ignores_alias_cardinality() -> None:
    one_root_aliases = physical_tag_evidence(("schtasks",), one_root=True)
    two_roots = physical_tag_evidence(("schtasks_create", "powershell_exec"))

    alias_vector = behavior_vector_from_scan("other", "sample.bin", one_root_aliases)
    two_root_vector = behavior_vector_from_scan("other", "sample.bin", two_roots)
    tag_count = PROFILE_VECTOR_FEATURE_NAMES.index("tag_count")

    assert alias_vector[tag_count] == 1.0 / 60.0
    assert two_root_vector[tag_count] == 2.0 / 60.0
    if "unique_tag_count" in PROFILE_VECTOR_FEATURE_NAMES:
        unique_tag_count = PROFILE_VECTOR_FEATURE_NAMES.index("unique_tag_count")
        assert alias_vector[unique_tag_count] == 1.0 / 60.0
        assert two_root_vector[unique_tag_count] == 2.0 / 60.0


def test_stage2636_08_attack_classifier_does_not_multiply_one_root_aliases() -> None:
    one_root = physical_tag_evidence(("shadowcopy_delete",), one_root=True)
    independent_roots = physical_tag_evidence((
        "shadowcopy_delete", "recovery_disable", "defender_disable",
    ))

    one_chain = evaluate_chain_evidence(tags=one_root)
    independent_chain = evaluate_chain_evidence(tags=independent_roots)
    one_result = compute_attack_intelligence(one_root, ())
    independent_result = compute_attack_intelligence(independent_roots, ())

    one_defense = next(record for record in one_result["classifier_records"] if record["classifier_id"] == "defense_evasion")
    independent_defense = next(record for record in independent_result["classifier_records"] if record["classifier_id"] == "defense_evasion")
    one_chain_probability, one_chain_reason = chain_probability_component(one_chain)
    independent_chain_probability, independent_chain_reason = chain_probability_component(independent_chain)

    assert one_defense["raw_score"] == 8.0
    assert one_defense["direct_evidence_count"] == 1
    assert independent_defense["raw_score"] > one_defense["raw_score"]
    assert independent_defense["direct_evidence_count"] == 3
    assert independent_result["aggregate_probability"] > one_result["aggregate_probability"]
    assert independent_result["best_family"] == "defense_evasion"
    assert independent_chain_probability > one_chain_probability
    assert one_chain_reason is None
    assert independent_chain_reason is None
    assert "chain_probability" not in independent_result


def test_stage2636_08_classifier_result_rejects_hookable_container_values() -> None:
    calls = {"iter": 0, "float": 0}

    class HostileRoots:
        def __iter__(self):
            calls["iter"] += 1
            raise AssertionError("root iterator hook invoked")

    class HostilePoints:
        def __float__(self):
            calls["float"] += 1
            raise AssertionError("numeric hook invoked")

    contribution = ClassifierContribution(HostileRoots(), HostilePoints(), "unsafe")
    result = ClassifierEvidenceResult(HostileRoots(), HostileRoots())

    assert contribution.root_observation_ids == ()
    assert contribution.points == 0.0
    assert result.contributions == ()
    assert result.informational_hits == ()
    assert calls == {"iter": 0, "float": 0}


def test_stage2636_08_graph_canonical_records_are_the_only_tag_projection_owner() -> None:
    evidence = physical_tag_evidence(("process_exec",), one_root=True)
    reset_graph_state()
    update_graph_node_owned(
        "sample.bin",
        tags=("unowned_display_tag",),
        tag_evidence_records=evidence.records,
    )
    add_graph_edge_owned(
        "sample.bin", "tag:persistence", edge_type="tag", weight=1.0,
    )
    update_graph_node_owned("sample.bin", tags=("network_exfiltration",))

    snapshot = graph_node_snapshot("sample.bin")

    assert snapshot is not None
    assert snapshot["tag_evidence_records"] == evidence.records
    assert snapshot["tags"] == frozenset(evidence.tags)
    assert "persistence" not in snapshot["tags"]
    assert "network_exfiltration" not in snapshot["tags"]


def test_stage2636_08_static_layer_never_rescores_canonical_chain_roots() -> None:
    one_root = physical_tag_evidence(("certutil_exec",), one_root=True)
    independent_roots = physical_tag_evidence(("certutil_exec", "network_download"))
    one_chain = evaluate_chain_evidence(tags=one_root)
    independent_chain = evaluate_chain_evidence(tags=independent_roots)

    one_result = compute_quick_static_layer(one_root, one_chain)
    independent_result = compute_quick_static_layer(
        independent_roots, independent_chain,
    )

    assert not any("downloader_static" in hit for hit in one_result["hits"])
    assert not any("downloader_static" in hit for hit in independent_result["hits"])
    assert independent_chain.total_score_points > one_chain.total_score_points
    assert "static_observation:certutil_exec" not in one_result["hits"]
    assert "static_observation:certutil_exec" not in independent_result["hits"]
    assert "static_observation:network_download" not in independent_result["hits"]


def test_stage2636_08_behavior_bucket_uses_one_record_per_root() -> None:
    one_root = physical_tag_evidence(("shadowcopy_delete",), one_root=True)
    result = behavior_bucket_validation("other", "sample.exe", one_root)

    assert [record["tag"] for record in result["records"]] == [
        "shadowcopy_delete",
    ]
    assert result["filetype_validation"]["records"][0]["tag"] == (
        "shadowcopy_delete"
    )
