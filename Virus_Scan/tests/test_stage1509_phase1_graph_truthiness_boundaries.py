from __future__ import annotations

from unittest.mock import patch
from Virus_Scan.models.graph import features as graph_features
from Virus_Scan.models.graph import relationships as graph_relationships
from Virus_Scan.models.graph import risk as graph_risk


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
class HostileBoolReason:
    str_calls = 0

    def __bool__(self):  # pragma: no cover - guard against truthiness probes
        raise RuntimeError("reason truthiness was evaluated")

    def __str__(self):  # pragma: no cover - guard against caller-owned text hooks
        type(self).str_calls += 1
        raise RuntimeError("reason text hook was evaluated")


class HostileBoolMetric:
    float_calls = 0

    def __bool__(self):  # pragma: no cover - guard against `value or 0.0`
        raise RuntimeError("metric truthiness was evaluated")

    def __float__(self):  # pragma: no cover - guard against caller-owned numeric hooks
        type(self).float_calls += 1
        raise RuntimeError("metric numeric hook was evaluated")


class HostileBoolFlag:
    def __bool__(self):  # pragma: no cover - guard against bool(flag)
        raise RuntimeError("flag truthiness was evaluated")

    def __str__(self):
        return "not_true"


def test_stage1509_graph_features_do_not_truth_test_unavailable_reasons():
    reason = HostileBoolReason()
    with patch.object(
        graph_features,
        "graph_node_snapshot",
        lambda _node: {
            "edges": frozenset(),
            "edge_time": {},
            "weights": {},
            "types": {},
            "risk": 0.0,
            "last_seen": 1.0,
            "attention": 0.0,
            "risk_unavailable_reason": reason,
            "attention_unavailable_reason": None,
            "weight_unavailable_reasons": {},
            "tags": frozenset(),
        },
    ):
        evidence = graph_features.get_graph_features("node:stage1509")

    assert evidence["graph_features_ready"] is False
    assert evidence["graph_unavailable_reason"] == "unsupported_graph_text_type:HostileBoolReason"
    assert HostileBoolReason.str_calls == 0


def test_stage1509_graph_relationship_does_not_truth_test_ready_or_reason():
    reason = HostileBoolReason()
    with (
        patch.object(
            graph_relationships,
            "get_graph_node",
            lambda _node: {"edges": {"tag:execution"}, "tags": {"execution"}, "weights": {}, "types": {}},
        ),
        patch.object(
            graph_relationships,
            "get_graph_features",
            lambda _node: {
                "risk": 0.1,
                "base_risk": 0.1,
                "anomaly": 0.0,
                "graph_features_ready": HostileBoolFlag(),
                "graph_unavailable_reason": reason,
            },
        ),
    ):
        evidence = graph_relationships.compute_graph_relationship_layer(
            "node:stage1509",
            tags=physical_tag_evidence(("execution", "credential_access")),
        )

    assert evidence["graph_relationship_ready"] is False
    assert evidence["degraded"] is True
    assert evidence["unavailable_reason"] == "unsupported_graph_text_type:HostileBoolReason"
    assert HostileBoolReason.str_calls == 0
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True


def test_stage1509_graph_risk_wrapper_does_not_truth_test_numeric_evidence():
    with patch.object(
        graph_risk,
        "get_graph_risk_enhanced_evidence",
        lambda _node: {"risk": HostileBoolMetric(), "ready": True, "degraded": False},
    ):
        assert graph_risk.get_graph_risk_enhanced("node:stage1509") == 0.0
    assert HostileBoolMetric.float_calls == 0
