from collections.abc import Mapping

import pytest

from Virus_Scan.runtime.graph_state import graph_snapshot, reset_graph_state, update_graph_node_owned


def test_stage1136_graph_full_snapshot_freezes_nested_runtime_metadata():
    reset_graph_state()
    nested = {"chain": ["download", {"child": ["execute"]}], "score": 3}
    update_graph_node_owned("node:nested", tags=("execution",), metadata=nested)

    snapshot = graph_snapshot()
    node_snapshot = snapshot["node:nested"]

    assert isinstance(snapshot, Mapping)
    assert isinstance(node_snapshot, Mapping)
    assert node_snapshot["metadata"]["chain"][1]["child"] == ("execute",)
    with pytest.raises(TypeError):
        snapshot["node:new"] = {}
    with pytest.raises(TypeError):
        node_snapshot["metadata"]["chain"][1]["child"] += ("mutated",)

    nested["chain"][1]["child"].append("mutated-after-snapshot")
    assert node_snapshot["metadata"]["chain"][1]["child"] == ("execute",)


def test_stage1136_graph_full_snapshot_is_deterministically_ordered_and_detached():
    reset_graph_state()
    update_graph_node_owned("z-node", metadata={"values": ["z"]})
    update_graph_node_owned("a-node", metadata={"values": ["a"]})

    snapshot = graph_snapshot()
    assert tuple(snapshot.keys()) == ("a-node", "z-node")
    assert snapshot["a-node"]["metadata"]["values"] == ("a",)

    update_graph_node_owned("a-node", metadata={"values": ["changed"]})
    assert snapshot["a-node"]["metadata"]["values"] == ("a",)
