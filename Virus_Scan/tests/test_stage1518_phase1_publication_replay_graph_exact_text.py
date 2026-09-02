"""Stage 1518 Phase 1 publication/replay/graph exact-text boundary regressions."""
from __future__ import annotations

from Virus_Scan.models.replay.detachment import detach_replay_payload_value, replay_payload_key_order, safe_replay_text
from Virus_Scan.models.replay.payload_boundaries import first_safe_text, safe_truthy_replay_flag
from Virus_Scan.publication.model_evidence_projection.safe_mapping import json_value, safe_str, safe_text_present
from Virus_Scan.publication.model_evidence_projection.unavailable_projection import unavailable_reasons
from Virus_Scan.runtime import graph_state


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.bool_calls = 0
        obj.strip_calls = 0
        obj.str_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves caller-owned __str__ was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves caller-owned strip was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip was invoked")

    def __bool__(self):  # pragma: no cover - failure proves caller-owned truthiness was probed
        self.bool_calls += 1
        raise AssertionError("caller-owned text truthiness was probed")


def h(value: str) -> HostileText:
    return HostileText(value)


def assert_no_hooks(*values: HostileText) -> None:
    for value in values:
        assert value.bool_calls == 0
        assert value.strip_calls == 0
        assert value.str_calls == 0


def test_stage1518_publication_safe_mapping_detaches_hostile_text_without_hooks():
    key = h(" model ")
    value = h(" degraded ")

    assert safe_str(key) == " model "
    assert safe_text_present(value) is True
    projected = json_value({key: value})

    assert projected == {" model ": " degraded "}
    out_key = next(iter(projected))
    assert type(out_key) is str
    assert type(projected[out_key]) is str
    assert_no_hooks(key, value)


def test_stage1518_publication_unavailable_reason_projection_uses_exact_text():
    reason_key = h(" markov_unavailable_reason ")
    # Preserve spaces around key to prove built-in stripping is used after exact detachment.
    reason_key = h("markov_unavailable_reason")
    reason_value = h(" cold_start ")

    reasons, unavailable, failures = unavailable_reasons({reason_key: reason_value})

    assert reasons == {"markov": "cold_start"}
    assert unavailable == {}
    assert failures == ()
    assert_no_hooks(reason_key, reason_value)


def test_stage1518_replay_payload_detaches_hostile_text_keys_values_and_flags():
    key = h("status")
    value = h(" failed ")
    payload = detach_replay_payload_value({key: value})

    assert payload == {"status": " failed "}
    out_key = next(iter(payload))
    assert type(out_key) is str
    assert type(payload[out_key]) is str
    assert replay_payload_key_order(key) == "status"
    assert safe_replay_text(value) == " failed "
    assert safe_truthy_replay_flag(value) is True
    assert first_safe_text({"status": value}, "status") == "failed"
    assert_no_hooks(key, value)


def test_stage1518_runtime_graph_state_detaches_snapshot_keys_metadata_and_vectors():
    graph_state.reset_graph_state()
    node = h(" node-a ")
    dst = h("tag:credential_access")
    edge_type = h(" tag ")
    metadata_key = h(" owner ")
    metadata_value = h(" graph-model ")

    assert graph_state.graph_vector_node_key(node) == "node-a"
    graph_state.ensure_graph_node_owned(node)
    graph_state.add_graph_edge_owned(node, dst, edge_type=edge_type, weight=1.0)
    graph_state.update_graph_node_owned(node, **{metadata_key: metadata_value})

    snapshot = graph_state.graph_snapshot()
    assert list(snapshot.keys()) == ["node-a", "tag:credential_access"]
    node_snapshot = snapshot["node-a"]
    assert node_snapshot["owner"] == " graph-model "
    assert type(next(iter(snapshot.keys()))) is str
    assert type(node_snapshot["owner"]) is str

    node_rows = graph_state.graph_node_snapshots()
    assert node_rows[0][0] == "node-a"
    assert type(node_rows[0][0]) is str
    assert_no_hooks(node, dst, edge_type, metadata_key, metadata_value)
