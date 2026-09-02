"""Stage2636.09 canonical graph risk, attention, and execution contracts."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import pytest

from Virus_Scan.models.graph.contracts import (
    GRAPH_CONTEXT_BASELINE_VERSION,
    GRAPH_RISK_POLICY,
)
from Virus_Scan.models.graph.influence import integrate_graph_intelligence
from Virus_Scan.models.graph.risk import get_graph_risk_enhanced_evidence
from Virus_Scan.models.graph.snapshot import admitted_graph_snapshot
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    graph_node_snapshot,
    reset_graph_state,
    update_graph_node_owned,
)


@pytest.fixture(autouse=True)
def _clean_graph_state() -> None:
    reset_graph_state()
    yield
    reset_graph_state()


def _context() -> dict[str, str]:
    return {"engine": "unity", "extension": ".exe", "node_type": "binary"}


def _baseline(*, context_key: str | None = None) -> dict[str, object]:
    return {
        "version": GRAPH_CONTEXT_BASELINE_VERSION,
        "trusted": True,
        "support_count": 32,
        "context_key": context_key or "engine:unity|extension:.exe|node_type:binary",
        "median": {
            "structural": 0.15,
            "attention": 0.15,
            "execution": 0.05,
            "temporal": 0.05,
        },
        "iqr": {
            "structural": 0.08,
            "attention": 0.08,
            "execution": 0.08,
            "temporal": 0.08,
        },
    }


def _add_malicious_evidence(node: str) -> None:
    rows = (
        ("tag:process_injection", "behavior", 2.8, 0.98, "root:behavior"),
        ("api:VirtualAllocEx", "call", 3.0, 0.99, "root:alloc"),
        ("api:WriteProcessMemory", "call", 3.0, 0.99, "root:write"),
        ("phase:execution", "attack_phase", 2.5, 0.98, "root:phase"),
        ("yara:injection", "yara", 3.0, 0.99, "root:yara"),
        ("temporal:stage2", "temporal", 2.2, 0.95, "root:time"),
    )
    for destination, edge_type, weight, confidence, evidence_id in rows:
        add_graph_edge_owned(
            node,
            destination,
            edge_type,
            weight,
            evidence_id=evidence_id,
            confidence=confidence,
        )


def _component_metrics(record: dict[str, object]) -> tuple[float, ...]:
    return (
        float(record["risk"]),
        float(record["structural_risk"]),
        float(record["attention"]),
        float(record["execution"]),
        float(record["temporal_relationship_risk"]),
        float(record["context_baseline_anomaly"]),
        float(record["confidence"]),
    )


def test_stage2636_09_policy_is_immutable_and_evaluation_selected() -> None:
    assert GRAPH_RISK_POLICY.version == "graph_risk_policy_v3"
    assert GRAPH_RISK_POLICY.selection_evidence == "stage2636_09_labeled_validation_execution_weighted"
    assert GRAPH_RISK_POLICY.decision_threshold == 0.55
    assert GRAPH_RISK_POLICY.execution_weight == 0.42
    with pytest.raises(FrozenInstanceError):
        GRAPH_RISK_POLICY.execution_weight = 0.0


def test_stage2636_09_components_require_supporting_evidence() -> None:
    node = "component-support"
    update_graph_node_owned(node, context=_context())
    empty = get_graph_risk_enhanced_evidence(node)
    assert empty["ready"] is True
    assert empty["degraded"] is False
    assert empty["component_degraded"] is True
    assert empty["attention"] == 0.0
    assert empty["execution"] == 0.0
    assert empty["temporal_relationship_risk"] == 0.0
    assert empty["components"]["context_anomaly"]["ready"] is False

    _add_malicious_evidence(node)
    update_graph_node_owned(node, context=_context(), context_baseline=_baseline())
    supported = get_graph_risk_enhanced_evidence(node)
    assert supported["attention"] > 0.0
    assert supported["execution"] > 0.0
    assert supported["temporal_relationship_risk"] > 0.0
    assert supported["context_baseline_anomaly"] > 0.0
    assert supported["risk"] >= supported["structural_risk"]


def test_stage2636_09_baseline_is_context_bound_and_not_enhanced_minus_base() -> None:
    node = "context-baseline"
    _add_malicious_evidence(node)
    update_graph_node_owned(node, context=_context(), context_baseline=_baseline())
    matched = get_graph_risk_enhanced_evidence(node)
    assert matched["components"]["context_anomaly"]["ready"] is True
    assert matched["context_baseline_anomaly"] > 0.0
    assert matched["context_baseline_anomaly"] != pytest.approx(
        matched["risk"] - matched["structural_risk"]
    )

    update_graph_node_owned(
        node,
        context_baseline=_baseline(context_key="engine:other|extension:.exe|node_type:binary"),
    )
    mismatched = get_graph_risk_enhanced_evidence(node)
    anomaly = mismatched["components"]["context_anomaly"]
    assert anomaly["ready"] is False
    assert anomaly["unavailable_reason"] == "graph_context_baseline_context_mismatch"
    assert mismatched["ready"] is True
    assert mismatched["component_degraded"] is True


def test_stage2636_09_cache_binds_snapshot_and_invalidates_on_mutation() -> None:
    node = "cache-contract"
    _add_malicious_evidence(node)
    update_graph_node_owned(node, context=_context(), context_baseline=_baseline())
    first = get_graph_risk_enhanced_evidence(node)
    second = get_graph_risk_enhanced_evidence(node)
    assert first["source"] == "snapshot"
    assert second["source"] == "cache"
    assert second["cache_key"] == first["cache_key"]

    add_graph_edge_owned(
        node, "module:new", "generic", 0.5,
        evidence_id="root:mutation", confidence=0.9,
    )
    third = get_graph_risk_enhanced_evidence(node)
    assert third["source"] == "snapshot"
    assert third["cache_key"] != first["cache_key"]
    assert third["snapshot_digest"] != first["snapshot_digest"]


def test_stage2636_09_forged_snapshot_digest_fails_closed() -> None:
    node = "corrupt-snapshot"
    _add_malicious_evidence(node)
    snapshot = graph_node_snapshot(node)
    forged = dict(snapshot or {})
    forged["snapshot_digest"] = "0" * 64
    admitted, reason = admitted_graph_snapshot(forged)
    assert admitted is None
    assert reason == "graph_snapshot_digest_mismatch"


def test_stage2636_09_duplicate_evidence_and_explanations_do_not_amplify() -> None:
    node = "dedup-control"
    add_graph_edge_owned(
        node, "tag:one", "tag", 1.0,
        evidence_id="shared-root", confidence=0.9,
    )
    update_graph_node_owned(node, context=_context(), context_baseline=_baseline())
    control = get_graph_risk_enhanced_evidence(node)

    reset_graph_state()
    for index in range(10):
        add_graph_edge_owned(
            node, f"tag:alias:{index}", "tag", 1.0,
            evidence_id="shared-root", confidence=0.9,
        )
    update_graph_node_owned(node, context=_context(), context_baseline=_baseline())
    aliases = get_graph_risk_enhanced_evidence(node)
    assert _component_metrics(aliases) == _component_metrics(control)

    add_graph_edge_owned(
        node, "cluster:explanation", "cluster_explanation", 3.0,
        evidence_id="cluster-only", confidence=1.0,
    )
    explained = get_graph_risk_enhanced_evidence(node)
    assert _component_metrics(explained) == _component_metrics(aliases)
    assert explained["snapshot_digest"] != aliases["snapshot_digest"]


def test_stage2636_09_current_scan_cycle_is_excluded_from_scoring() -> None:
    node = "cycle-guard"
    add_graph_edge_owned(
        node, "module:raw", "generic", 0.5,
        evidence_id="raw-root", confidence=0.9,
    )
    integrate_graph_intelligence(node)
    snapshot = graph_node_snapshot(node)
    assert snapshot is not None
    assert snapshot["current_scan_cycle_guard"] == "graph_score_excludes_current_cluster"
    referenced_names = integrate_graph_intelligence.__code__.co_names
    assert "propagate_cluster_influence" not in referenced_names
    assert "reinforce_graph_with_cluster" not in referenced_names


def test_stage2636_09_exact_component_publication_contract() -> None:
    node = "publication-contract"
    _add_malicious_evidence(node)
    update_graph_node_owned(node, context=_context(), context_baseline=_baseline())
    record = get_graph_risk_enhanced_evidence(node)
    assert record["evidence_version"] == "graph_risk_evidence_v3"
    assert record["policy_version"] == GRAPH_RISK_POLICY.version
    assert record["decision_threshold"] == GRAPH_RISK_POLICY.decision_threshold
    assert record["policy_selection_evidence"] == GRAPH_RISK_POLICY.selection_evidence
    assert record["replay_record_required"] is True
    assert set(record["components"]) == {
        "structural", "attention", "execution", "temporal", "context_anomaly",
    }
    for name, component in record["components"].items():
        assert component["name"] == name
        assert isinstance(component["provenance"], tuple)
        assert component["version"]
