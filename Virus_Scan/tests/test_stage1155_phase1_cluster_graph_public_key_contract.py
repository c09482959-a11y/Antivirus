from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.tests.support.clustering_v2 import raw_cluster_vector

import ast
from pathlib import Path

from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import graph_vector_node_key
from Virus_Scan.models.clustering import assign_cluster_with_context_tags

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
CLUSTER_MODEL_DIR = Path("Virus_Scan/models/clustering")
GRAPH_MODEL = Path("Virus_Scan/models/graph")


def test_stage1155_clustering_uses_runtime_owned_graph_vector_key_not_graph_private_helper() -> None:
    cluster_source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(CLUSTER_MODEL_DIR.glob("*.py")))
    graph_source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(GRAPH_MODEL.glob("*.py")))

    tree = ast.parse(cluster_source, filename=str(CLUSTER_MODEL_DIR))
    private_graph_imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.models.graph"
        for alias in node.names
        if alias.name.startswith("_")
    }

    assert private_graph_imports == set()
    assert "def _vector_db_node_key" not in graph_source
    assert graph_vector_node_key(" node ") == "node"


def test_stage1155_cluster_assignment_accepts_runtime_owned_vector_key() -> None:
    configure_runtime_cluster_state(RuntimeClusterState())

    result = assign_cluster_with_context_tags(" node:cluster ", raw_cluster_vector(), tags=physical_tag_evidence(("tag_a",)), learning_decision=accepted_learning_decision(target_names=("clustering",)))

    assert isinstance(result, str) or result is None
