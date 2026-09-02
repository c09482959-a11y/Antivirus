"""Stage 1582: graph tag boundaries must reject unknown iterables without hooks."""

from __future__ import annotations

from Virus_Scan.models.graph.state import get_graph_node
from Virus_Scan.runtime.graph_state import graph_snapshot, reset_graph_state, update_graph_node_owned


class HostileTags:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise RuntimeError("do not iterate graph tags")

    def __repr__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise RuntimeError("do not repr graph tags")

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise RuntimeError("do not str graph tags")


def test_graph_update_unsupported_tags_emit_explicit_evidence_without_iteration() -> None:
    reset_graph_state()
    HostileTags.touched = 0

    update_graph_node_owned("node", tags=HostileTags())
    node = get_graph_node("node")

    assert HostileTags.touched == 0
    assert node is not None
    assert node["tags"] == frozenset()
    assert node["tags_unavailable_reason"] == "non_materializable_graph_tags"



class HostileMetadata:
    touched = 0

    def __repr__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise RuntimeError("do not repr graph metadata")

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise RuntimeError("do not str graph metadata")


def test_graph_update_metadata_rejects_unknown_object_before_runtime_storage() -> None:
    reset_graph_state()
    HostileMetadata.touched = 0

    update_graph_node_owned("node", external_metadata=HostileMetadata())
    snapshot = graph_snapshot()

    assert HostileMetadata.touched == 0
    assert snapshot["node"]["external_metadata"] == "graph_runtime_text_unavailable:HostileMetadata"
