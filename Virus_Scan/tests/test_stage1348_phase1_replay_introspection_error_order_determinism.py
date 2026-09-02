from Virus_Scan.models.replay_introspection import ReplayNode, validate_replay_lineage


def _fanout_nodes(order: tuple[str, str]) -> list[ReplayNode]:
    groups = {
        "parent_a": [
            ReplayNode("parent_a"),
            ReplayNode("a_child_1", "parent_a"),
            ReplayNode("a_child_2", "parent_a"),
        ],
        "parent_b": [
            ReplayNode("parent_b"),
            ReplayNode("b_child_1", "parent_b"),
            ReplayNode("b_child_2", "parent_b"),
        ],
    }
    nodes: list[ReplayNode] = []
    for key in order:
        nodes.extend(groups[key])
    return nodes


def test_replay_lineage_fanout_errors_are_sorted_by_parent_id() -> None:
    first = validate_replay_lineage(_fanout_nodes(("parent_a", "parent_b")), max_fanout=1)
    second = validate_replay_lineage(_fanout_nodes(("parent_b", "parent_a")), max_fanout=1)

    expected = [
        "fanout_exceeded:parent_a:2>1",
        "fanout_exceeded:parent_b:2>1",
    ]
    assert first["errors"] == expected
    assert second["errors"] == expected


def test_replay_lineage_graph_summary_is_stable_for_equivalent_fanout_input() -> None:
    first = validate_replay_lineage(_fanout_nodes(("parent_a", "parent_b")), max_fanout=1)
    second = validate_replay_lineage(_fanout_nodes(("parent_b", "parent_a")), max_fanout=1)

    assert first["fanout_max"] == second["fanout_max"] == 2
    assert first["nodes"] == second["nodes"] == 6
    assert first["depth"] == second["depth"] == 2
    assert first["graph"] == second["graph"]
