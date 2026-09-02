"""Stage 1514 Phase 1 publication contract text-boundary regressions."""
from __future__ import annotations

from unittest.mock import patch
from Virus_Scan.publication.model_evidence_projection.contract_sanitization import sanitize_contract_record
from Virus_Scan.publication.model_evidence_projection.probability_validation import valid_probability_flow
from Virus_Scan.publication.model_evidence_projection.record_validation import valid_replay_mismatch_fields
from Virus_Scan.publication.model_evidence_projection.safe_mapping import safe_str
from Virus_Scan.publication.model_evidence_projection.unavailable_projection import (
    nested_model_signal_unavailable_reasons,
    sanitize_existing_unavailable_reasons_record,
    unavailable_reasons,
)
from Virus_Scan.models.clustering import vectors


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.bool_calls = 0
        return obj

    def __str__(self):
        return self

    def strip(self, *args, **kwargs):
        return self

    def __bool__(self):  # pragma: no cover - failure proves boundary regression
        self.bool_calls += 1
        raise AssertionError("publication contract text boundary truth-tested caller-owned text")


def test_stage1514_safe_str_detaches_hostile_str_subclass_without_truthiness():
    value = HostileText("model_v1")

    materialized = safe_str(value)

    assert materialized == "model_v1"
    assert type(materialized) is str
    assert value.bool_calls == 0


def test_stage1514_probability_record_contract_sanitization_does_not_truth_test_text():
    smoothing = HostileText("laplace")
    reason = HostileText("cold_start")
    version = HostileText("markov_v1")
    flow_a = HostileText("archive")
    flow_b = HostileText("runtime")

    sanitized, unavailable, failures = sanitize_contract_record(
        "markov_probability_record",
        {
            "ready": False,
            "probability": None,
            "support": 0,
            "count": 0,
            "vocab": 2,
            "smoothing": smoothing,
            "reason": reason,
            "model_version": version,
            "flow": (flow_a, flow_b),
        },
    )

    assert sanitized["smoothing"] == "laplace"
    assert sanitized["reason"] == "cold_start"
    assert sanitized["model_version"] == "markov_v1"
    assert sanitized["flow"] == ("archive", "runtime")
    assert unavailable == {}
    assert failures == ()
    assert smoothing.bool_calls == 0
    assert reason.bool_calls == 0
    assert version.bool_calls == 0
    assert flow_a.bool_calls == 0
    assert flow_b.bool_calls == 0


def test_stage1514_probability_and_replay_sequence_validators_do_not_truth_test_text():
    flow_a = HostileText("extract")
    flow_b = HostileText("execute")
    mismatch = HostileText("feature_probabilities.markov")

    flow, flow_reason = valid_probability_flow((flow_a, flow_b))
    fields, field_reason = valid_replay_mismatch_fields((mismatch,))

    assert flow == ("extract", "execute")
    assert flow_reason == ""
    assert fields == ("feature_probabilities.markov",)
    assert field_reason == ""
    assert flow_a.bool_calls == 0
    assert flow_b.bool_calls == 0
    assert mismatch.bool_calls == 0


def test_stage1514_unavailable_reason_projection_detaches_hostile_text():
    key = HostileText("markov_unavailable_reason")
    value = HostileText("cold_start")
    existing_key = HostileText("temporal")
    existing_value = HostileText("insufficient_support")

    projected, unavailable, failures = unavailable_reasons({key: value})
    existing, existing_unavailable, existing_failures = sanitize_existing_unavailable_reasons_record(
        {existing_key: existing_value}
    )

    assert projected == {"markov": "cold_start"}
    assert unavailable == {}
    assert failures == ()
    assert existing == {"temporal": "insufficient_support"}
    assert existing_unavailable == {}
    assert existing_failures == ()
    assert key.bool_calls == 0
    assert value.bool_calls == 0
    assert existing_key.bool_calls == 0
    assert existing_value.bool_calls == 0


def test_stage1514_nested_model_signal_unavailable_reasons_do_not_truth_test_text():
    key = HostileText("profile")
    value = HostileText("invalid_profile")

    reasons, unavailable, failures = nested_model_signal_unavailable_reasons(
        {
            "profile_selection": {
                "unavailable_reasons": {key: value},
                "details": {"ignored": "non_model_reason"},
            }
        }
    )

    assert reasons == {"profile_selection.profile": "invalid_profile"}
    assert unavailable == {}
    assert failures == ()
    assert key.bool_calls == 0
    assert value.bool_calls == 0


def test_stage1514_cluster_feature_vector_does_not_truth_test_cluster_id():
    cid = HostileText("cluster-a")
    seen = {}

    with (
        patch.object(vectors, "cluster_graph_node_key", lambda _node: "node-a"),
        patch.object(vectors, "node_cluster_map", lambda: {"node-a": cid}),
        patch.object(vectors, "vector_cluster_members_for", lambda cluster_id: seen.setdefault("cid", cluster_id) or {"node-a"}),
    ):
        vector = vectors.build_feature_vector(
            "node-a",
            tags=("network_download",),
            graph_features={},
            temporal_features={},
            markov_features={},
            engine_context={"unity": 1.0},
        )

    assert seen["cid"] == "cluster-a"
    assert len(vector) > 0
    assert cid.bool_calls == 0
