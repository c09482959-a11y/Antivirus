from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.models.replay_introspection import (
    ReplayNode,
    validate_replay_lineage,
    why_suspicious_report,
)



class HostileText:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned repr hook was invoked")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")


def test_stage2023_replay_lineage_errors_use_primitive_formatting() -> None:
    nodes = [
        ReplayNode("root"),
        ReplayNode("root"),
        ReplayNode("child_a", "root"),
        ReplayNode("child_b", "root"),
    ]

    result = validate_replay_lineage(nodes, max_depth=1, max_fanout=1, max_nodes=2)

    assert result["ok"] is False
    assert "duplicate_node:root" in result["errors"]
    assert "nodes_exceeded:4>2" in result["errors"]
    assert "depth_exceeded:2>1" in result["errors"]
    assert "fanout_exceeded:root:2>1" in result["errors"]
    assert result["fanout_max"] == 2


def test_stage2023_replay_introspection_report_uses_no_hook_mapping_items() -> None:
    report = why_suspicious_report(
        [
            ReplayNode("root", influence=0.1),
            ReplayNode("child", "root", influence=0.9),
        ]
    )

    assert report["graph_summary"] == {"nodes": 2, "depth": 2}
    assert report["top_influences"][0][0] == "child"


def test_stage2023_replay_introspection_rejects_requested_node_hooks() -> None:
    HostileText.touched = 0

    report = why_suspicious_report([ReplayNode("root")], node_id=HostileText())

    assert report["graph_summary"] == {"nodes": 1, "depth": 1}
    assert "top_influences" in report
    assert HostileText.touched == 0


def test_stage2023_replay_introspection_source_removed_backlog_hook_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/models/replay_introspection.py"))

    forbidden = (
        "return None",
        'errors.append(f"duplicate_node:',
        'errors.append(f"cycle:',
        'errors.append(f"nodes_exceeded:',
        'errors.append(f"depth_exceeded:',
        'errors.append(f"fanout_exceeded:',
        "fanout.values()",
        'graph["attribution"].items()',
    )
    for snippet in forbidden:
        assert snippet not in source
