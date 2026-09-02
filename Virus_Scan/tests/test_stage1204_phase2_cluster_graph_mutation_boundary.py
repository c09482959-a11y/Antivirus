from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.tests.support.clustering_v2 import raw_cluster_vector

import ast
from pathlib import Path

from Virus_Scan.models.clustering import assign_cluster_with_context_tags
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import graph_node_snapshot, reset_graph_state

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
CLUSTERING_MODEL_DIR = Path("Virus_Scan/models/clustering")


def test_stage1204_clustering_does_not_import_graph_model() -> None:
    cluster_source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(CLUSTERING_MODEL_DIR.glob("*.py")))
    tree = ast.parse(cluster_source, filename=str(CLUSTERING_MODEL_DIR))
    graph_imports = [
        (node.lineno, node.module)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.models.graph"
    ]

    assert graph_imports == []


def test_stage1204_clustering_does_not_call_graph_edge_writer() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(CLUSTERING_MODEL_DIR.glob("*.py")))

    assert "add_graph_edge(" not in source
    assert "edge_type='cluster'" not in source


def test_stage1204_cluster_assignment_does_not_mutate_graph_edges() -> None:
    configure_runtime_cluster_state(RuntimeClusterState())
    reset_graph_state()

    cluster_id = assign_cluster_with_context_tags("node:cluster", raw_cluster_vector(), tags=physical_tag_evidence(("tag_a",)), learning_decision=accepted_learning_decision(target_names=("clustering",)))

    assert isinstance(cluster_id, str)
    assert graph_node_snapshot("node:cluster") is None
