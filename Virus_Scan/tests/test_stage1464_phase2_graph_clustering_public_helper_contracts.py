import ast
from pathlib import Path

from Virus_Scan.models.clustering import metadata as clustering_metadata
from Virus_Scan.models.clustering import similarity as clustering_similarity
from Virus_Scan.models.graph import attention as graph_attention
from Virus_Scan.models.graph import features as graph_features

CLUSTERING_CONSUMERS = (
    Path("Virus_Scan/models/clustering/assignment.py"),
    Path("Virus_Scan/models/clustering/explain.py"),
)
GRAPH_CONSUMERS = (
    Path("Virus_Scan/models/graph/features.py"),
    Path("Virus_Scan/models/graph/relationships.py"),
)
FORBIDDEN_PRIVATE_IMPORTS = (
    "_cluster_kind_for_tags",
    "_cluster_engine_prefix",
    "_cluster_decay",
    "_cluster_similarity",
    "_graph_snapshot_corruption_reason",
    "_unavailable_graph_features",
)


def _imported_private_names(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.extend(alias.name for alias in node.names if alias.name in FORBIDDEN_PRIVATE_IMPORTS)
    return tuple(sorted(names))


def test_stage1464_clustering_consumers_use_public_metadata_owner_names():
    leaked = {str(path): _imported_private_names(path) for path in CLUSTERING_CONSUMERS}
    assert leaked == {str(path): () for path in CLUSTERING_CONSUMERS}
    for name in ("cluster_kind_for_tags", "cluster_engine_prefix", "cluster_decay"):
        assert hasattr(clustering_metadata, name)
        assert name in clustering_metadata.__all__
    assert hasattr(clustering_similarity, "cluster_similarity")
    assert "cluster_similarity" in clustering_similarity.__all__


def test_stage1464_graph_consumers_use_public_feature_and_attention_owner_names():
    leaked = {str(path): _imported_private_names(path) for path in GRAPH_CONSUMERS}
    assert leaked == {str(path): () for path in GRAPH_CONSUMERS}
    assert hasattr(graph_attention, "graph_snapshot_corruption_reason")
    assert "graph_snapshot_corruption_reason" in graph_attention.__all__
    assert hasattr(graph_features, "unavailable_graph_features")
    assert "unavailable_graph_features" in graph_features.__all__
