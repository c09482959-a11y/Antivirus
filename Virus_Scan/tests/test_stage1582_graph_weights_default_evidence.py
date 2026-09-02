"""Stage 1582: graph weight fallbacks must emit explicit evidence."""

from __future__ import annotations

from Virus_Scan.models.graph.state import get_graph_node
from Virus_Scan.runtime.graph_state import reset_graph_state, update_graph_node_owned


class HostileWeights:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise RuntimeError("do not iterate graph weights")

    def __repr__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise RuntimeError("do not repr graph weights")

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise RuntimeError("do not str graph weights")


def test_graph_update_unsupported_weights_emit_explicit_evidence_without_hooks() -> None:
    reset_graph_state()
    HostileWeights.touched = 0

    update_graph_node_owned("node", weights=HostileWeights())
    node = get_graph_node("node")

    assert HostileWeights.touched == 0
    assert node is not None
    assert node["weights"] == {}
    assert node["weight_unavailable_reasons"] == {
        "__weights__": "non_materializable_graph_weights"
    }
