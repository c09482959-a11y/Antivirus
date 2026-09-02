from __future__ import annotations

import ast
from pathlib import Path

import Virus_Scan.models.clustering.state as cluster_state_owner
import Virus_Scan.models.graph.common as graph_common


def test_stage1463_graph_common_helpers_are_public_owner_names():
    public_names = set(graph_common.__all__)
    required = {
        "safe_graph_text",
        "safe_graph_text_with_reason",
        "safe_graph_sequence",
        "normalize_graph_tags_with_reason",
        "record_graph_input_degraded",
        "safe_graph_metadata_value",
        "coerce_graph_event_time",
        "graph_event_time_failure_reason",
    }
    assert required <= public_names
    forbidden = {f"_{name}" for name in required}
    assert public_names.isdisjoint(forbidden)
    for name in forbidden:
        assert not hasattr(graph_common, name)


def test_stage1463_graph_modules_do_not_import_private_common_helpers():
    offenders = []
    for path in sorted(Path("Virus_Scan/models/graph").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.models.graph.common":
                offenders.extend(
                    f"{path}:{node.lineno}:{alias.name}"
                    for alias in node.names
                    if alias.name.startswith("_") and not alias.name.startswith("__")
                )
    assert offenders == []


def test_stage1463_clustering_state_accessors_are_public_owner_names():
    public_names = set(cluster_state_owner.__all__)
    required = {
        "node_cluster_map",
        "malicious_clusters",
        "benign_clusters",
        "mixed_clusters",
        "cluster_metadata",
        "cluster_signatures",
        "node_feature_vectors",
        "cluster_tag_signatures",
        "cluster_lock",
        "cluster_graph_node_key",
        "ClusterGraphNodeRecord",
        "cluster_graph_node_snapshot",
        "cluster_node_key",
    }
    assert required <= public_names
    for name in required:
        assert callable(getattr(cluster_state_owner, name))
        assert not hasattr(cluster_state_owner, f"_{name}")


def test_stage1463_clustering_modules_do_not_import_private_state_helpers():
    offenders = []
    for path in sorted(Path("Virus_Scan/models/clustering").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.models.clustering.state":
                offenders.extend(
                    f"{path}:{node.lineno}:{alias.name}"
                    for alias in node.names
                    if alias.name.startswith("_") and not alias.name.startswith("__")
                )
    assert offenders == []
