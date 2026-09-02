import json

from Virus_Scan.models.api import graph_contracts
from Virus_Scan.models.contracts.model_failure import (
    make_model_failure_record,
    materialize_model_failure_record,
)
from Virus_Scan.models.contracts.model_snapshot import (
    make_model_snapshot,
    materialize_model_snapshot,
)
from Virus_Scan.models.temporal.event_materialization import (
    materialize_temporal_events,
)
from Virus_Scan.runtime.temporal_state import (
    temporal_node_state_snapshot,
    temporal_state_node_key,
)


class BadStr:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("string conversion unavailable")

    def __hash__(self):
        return id(self)


def test_stage1407_failure_and_snapshot_contracts_do_not_leak_bad_str_objects():
    failure = materialize_model_failure_record(
        make_model_failure_record(
            model_name="profiles", failure_type="corrupt_profile",
            reason="bad input", details={"hostile_set": {BadStr()}},
        )
    )
    snapshot = materialize_model_snapshot(
        make_model_snapshot(
            {"hostile_set": {BadStr()}}, model_name="runtime_model_state",
            snapshot_type="model_state", model_version="stage1407_test",
        )
    )

    assert failure["details"]["hostile_set"][0]["unavailable_reason"] == "unsupported_model_failure_detail_value"
    assert snapshot["values"]["hostile_set"][0]["unavailable_reason"] == "unsupported_model_snapshot_value"
    json.dumps(failure, sort_keys=True)
    json.dumps(snapshot, sort_keys=True)


def test_stage1407_graph_relationship_tags_with_bad_str_degrade_without_crash():
    evidence = graph_contracts.compute_graph_relationship_layer(
        "stage1407-node", tags={BadStr()},
    )
    assert evidence["graph_relationship_ready"] is False
    assert evidence["graph_unavailable_reason"] == "unreadable_graph_relationship_tags"


def test_stage1407_temporal_v5_boundaries_never_stringify_bad_objects():
    BadStr.touched = 0
    events, validations = materialize_temporal_events(
        ordered_events=({"tag": BadStr()},), behavior_flow=(),
        observation_id="stage1407", previous_stage="asset",
        current_stage="runtime",
    )
    assert events == ()
    assert validations[0].status == "unavailable"
    assert "temporal_behavior_unavailable" in validations[0].reasons
    assert temporal_state_node_key(BadStr()) == "<BadStr>"
    snapshot = temporal_node_state_snapshot(BadStr())
    assert snapshot["history"] == ()
    assert BadStr.touched == 0


from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def test_stage1407_publication_model_evidence_bad_probability_key_is_json_safe():
    fields = build_model_evidence_final_json_fields({
        "model_evidence": {"temporal_overlay": {
            "ready": False, "probability": None, "support": 0,
            "count": 0, "vocab": 0, "smoothing": "none",
            "reason": "cold_start", "model_version": "stage1407_test",
            "pair_probabilities": {BadStr(): 0.5},
        }}
    })
    nested = fields["model_evidence"]["temporal_overlay"]["pair_probabilities"]["<BadStr>"]
    assert nested["unavailable_reason"] == "unreadable_json_mapping_key"
    json.dumps(fields, sort_keys=True)
