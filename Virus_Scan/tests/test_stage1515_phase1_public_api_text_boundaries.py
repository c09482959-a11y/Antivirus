"""Stage 1515 Phase 1 public model API text-boundary regressions."""
from __future__ import annotations

from unittest.mock import patch
from Virus_Scan.models.api import clustering_contracts, graph_contracts, profile_contracts, profile_learning_contracts, profile_retention_contracts, replay_comparison_contracts
from Virus_Scan.models.behavior_sequence_contract import _model_sequence_detached_text
from Virus_Scan.models.graph.common import graph_first_reason, safe_graph_text, safe_graph_text_with_reason


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.bool_calls = 0
        obj.strip_calls = 0
        return obj

    def __str__(self):
        return self

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves raw caller strip was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip was invoked")

    def __bool__(self):  # pragma: no cover - failure proves truthiness regression
        self.bool_calls += 1
        raise AssertionError("caller-owned text truthiness was probed")


def test_stage1515_public_model_contract_text_helpers_detach_hostile_strings():
    key = HostileText(" model ")
    value = HostileText(" unavailable ")

    graph_value = graph_contracts._immutable_graph_value({key: value})
    cluster_value = clustering_contracts._immutable_cluster_value({key: value})
    profile_value = profile_contracts._immutable_profile_value({key: value})
    profile_learning_value = profile_learning_contracts._immutable_profile_learning_value({key: value})
    retention_value = profile_retention_contracts._immutable_retention_value({key: value})

    assert graph_value == {"model": "unavailable"}
    assert cluster_value == {"model": "unavailable"}
    assert profile_value == {"model": "unavailable"}
    assert profile_learning_value == {"model": "unavailable"}
    assert retention_value == {"model": "unavailable"}
    assert type(next(iter(graph_value.keys()))) is str
    assert type(graph_value["model"]) is str
    assert type(next(iter(cluster_value.keys()))) is str
    assert type(cluster_value["model"]) is str
    assert type(next(iter(profile_value.keys()))) is str
    assert type(profile_value["model"]) is str
    assert type(next(iter(profile_learning_value.keys()))) is str
    assert type(profile_learning_value["model"]) is str
    assert type(next(iter(retention_value.keys()))) is str
    assert type(retention_value["model"]) is str
    assert key.bool_calls == 0
    assert value.bool_calls == 0
    assert key.strip_calls == 0
    assert value.strip_calls == 0


def test_stage1515_replay_comparison_reason_detaches_hostile_text():
    reason = HostileText(" replay mismatch ")

    comparison = replay_comparison_contracts.compare_model_evidence(
        model_name="markov",
        expected={"probability": 0.5},
        actual={"probability": 0.6},
        reason=reason,
    )

    assert comparison["reason"] == "replay mismatch"
    assert type(comparison["reason"]) is str
    assert reason.bool_calls == 0
    assert reason.strip_calls == 0


def test_stage1515_behavior_sequence_text_boundary_uses_exact_string_materialization():
    tag = HostileText(" behavior_tag ")
    fallback = HostileText(" fallback ")
    blank = HostileText("   ")

    assert _model_sequence_detached_text(tag, default_text=fallback) == "behavior_tag"
    assert _model_sequence_detached_text(blank, default_text=fallback) == " fallback "
    assert tag.bool_calls == 0
    assert fallback.bool_calls == 0
    assert blank.bool_calls == 0
    assert tag.strip_calls == 0
    assert fallback.strip_calls == 0
    assert blank.strip_calls == 0


def test_stage1515_graph_common_text_helpers_do_not_call_hostile_strip_or_bool():
    reason = HostileText(" graph degraded ")
    fallback = HostileText(" fallback degraded ")

    assert safe_graph_text(reason) == " graph degraded "
    text, unavailable = safe_graph_text_with_reason(reason, "bad_graph_text")
    assert text == "graph degraded"
    assert unavailable == ""
    assert graph_first_reason(None, reason, fallback) == "graph degraded"
    assert reason.bool_calls == 0
    assert fallback.bool_calls == 0
    assert reason.strip_calls == 0
    assert fallback.strip_calls == 0


def test_stage1515_public_graph_risk_evidence_materializes_owner_text():
    reason = HostileText(" graph unavailable ")

    with patch.object(
        graph_contracts,
        "owner_get_graph_risk_enhanced_evidence",
        lambda _node: {"risk": 0.0, "ready": False, "degraded": True, "unavailable_reason": reason},
    ):
        evidence = graph_contracts.get_graph_risk_enhanced_evidence("node-a")

    assert evidence["unavailable_reason"] == "graph unavailable"
    assert type(evidence["unavailable_reason"]) is str
    assert reason.bool_calls == 0
    assert reason.strip_calls == 0


def test_stage1515_public_profile_text_helpers_detach_engine_text():
    engine = HostileText(" renpy ")
    expected = {}

    def fake_default_engine_profile(engine_name):
        expected["engine"] = engine_name
        return {"engine": engine_name}

    with patch.object(profile_contracts, "owner_default_engine_profile", fake_default_engine_profile):
        profile = profile_contracts.default_engine_profile(engine)

    assert expected["engine"] == "renpy"
    assert type(expected["engine"]) is str
    assert profile["engine"] == "renpy"
    assert engine.bool_calls == 0
    assert engine.strip_calls == 0
