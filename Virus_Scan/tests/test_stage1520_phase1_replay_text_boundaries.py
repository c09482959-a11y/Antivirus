"""Stage 1520: replay introspection/economics text must detach hostile strings."""

from Virus_Scan.models.replay_economics import (
    ReplayEconomicsConfig,
    replay_compress_metadata,
    replay_should_retain,
)
from Virus_Scan.models.replay_introspection import (
    ReplayNode,
    compress_replay_nodes,
    replay_influence_graph,
    why_suspicious_report,
)


class _HostileText(str):
    def __str__(self):  # pragma: no cover - exercised only if boundary regresses
        raise RuntimeError("hostile __str__")

    def strip(self, *args, **kwargs):  # pragma: no cover - exercised only if boundary regresses
        raise RuntimeError("hostile strip")

    def __bool__(self):  # pragma: no cover - exercised only if boundary regresses
        raise RuntimeError("hostile bool")


class _HostileObject:
    def __str__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("hostile object string")


def test_stage1520_replay_node_fields_are_exact_text_without_hostile_hooks():
    node = ReplayNode(
        _HostileText("child"),
        _HostileText("root"),
        (_HostileText("tag"),),
        0.4,
        _HostileText("origin"),
        _HostileText("rationale"),
    )

    assert node.node_id == "child"
    assert node.parent_id == "root"
    assert node.tags == ("tag",)
    assert node.origin == "origin"
    assert node.rationale == "rationale"
    assert type(node.node_id) is str
    assert type(node.tags[0]) is str


def test_stage1520_replay_reports_do_not_truthiness_probe_requested_node_id():
    nodes = [ReplayNode(_HostileText("root")), ReplayNode(_HostileText("child"), _HostileText("root"))]

    graph = replay_influence_graph(nodes)
    report = why_suspicious_report(nodes, node_id=_HostileText("child"))

    assert graph["edges"] == [{"parent": "root", "child": "child", "influence": 0.0}]
    assert report["node"] == "child"
    assert report["inheritance_chain"][0]["node"] == "child"


def test_stage1520_replay_compression_does_not_truthiness_probe_origin_or_rationale():
    nodes = (
        ReplayNode("child", "root", ("a",), 0.2, _HostileText(""), _HostileText("first")),
        ReplayNode("child", "root", ("b",), 0.5, _HostileText("owner"), _HostileText("second")),
    )

    merged = compress_replay_nodes(nodes)

    assert len(merged) == 1
    assert merged[0].origin == "owner"
    assert merged[0].rationale == "first"
    assert type(merged[0].origin) is str


def test_stage1520_replay_economics_metadata_detaches_keys_and_values():
    compressed = replay_compress_metadata({
        _HostileText("k2"): _HostileText("value"),
        _HostileText("raw"): _HostileText("discarded"),
        _HostileText("bad"): _HostileObject(),
    })

    assert compressed["k2"] == "value"
    assert "raw" not in compressed
    assert compressed["bad"] == {
        "value": "<_HostileObject>",
        "unavailable_reason": "unsupported_replay_metadata_type",
    }
    assert all(type(key) is str for key in compressed)


def test_stage1520_replay_retain_identity_detaches_hostile_path_text():
    retained = replay_should_retain(
        {"path": _HostileText("archive/game.zip"), "score": 0, "replay_divergence": False},
        index=1,
        config=ReplayEconomicsConfig(sample_modulo=1),
    )

    assert retained is True
