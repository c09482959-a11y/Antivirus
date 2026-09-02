from __future__ import annotations

import ast
from pathlib import Path

import Virus_Scan.models.api as model_api
from Virus_Scan.models import clustering, graph, temporal
from Virus_Scan.models.api import clustering_contracts, graph_contracts, temporal_contracts
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES

REPO = Path(__file__).resolve().parents[2]


def _imports_from(path: str) -> set[str]:
    root = REPO / path
    source_paths = sorted(root.glob("*.py")) if root.is_dir() else [root]
    imports: set[str] = set()
    for source_path in source_paths:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
    return imports


def test_runtime_observation_contracts_are_public_model_api() -> None:
    assert "clustering_contracts" in model_api.__all__
    assert "graph_contracts" in model_api.__all__
    assert "temporal_contracts" in model_api.__all__
    assert "Virus_Scan.models.api.clustering_contracts" in MODEL_BOOTSTRAP_MODULE_NAMES
    assert "Virus_Scan.models.api.graph_contracts" in MODEL_BOOTSTRAP_MODULE_NAMES
    assert "Virus_Scan.models.api.temporal_contracts" in MODEL_BOOTSTRAP_MODULE_NAMES


def test_profiles_use_public_model_contracts_and_replay_is_evidence_only() -> None:
    profile_imports = _imports_from("Virus_Scan/models/profiles")
    replay_imports = _imports_from("Virus_Scan/models/replay")
    for imports in (profile_imports, replay_imports):
        assert "Virus_Scan.models.clustering" not in imports
        assert "Virus_Scan.models.graph" not in imports
        assert "Virus_Scan.models.temporal" not in imports
        assert "Virus_Scan.models.temporal.state_projection" not in imports
    assert "Virus_Scan.models.api.clustering_contracts" in profile_imports
    assert "Virus_Scan.models.api.temporal_contracts" in profile_imports
    assert "Virus_Scan.models.api.graph_contracts" not in profile_imports
    for module in (
        "Virus_Scan.models.api.clustering_contracts",
        "Virus_Scan.models.api.graph_contracts",
        "Virus_Scan.models.api.temporal_contracts",
    ):
        assert module not in replay_imports


def test_runtime_observation_contracts_preserve_canonical_owner_functions() -> None:
    assert clustering_contracts.VECTOR_FEATURE_NAMES == tuple(clustering.VECTOR_FEATURE_NAMES)
    assert temporal_contracts.snapshot_temporal("stage1232-missing-node") == temporal.snapshot_temporal(
        "stage1232-missing-node"
    )
    vector_baseline = {"count": 0, "mean": [], "m2": [], "variance": [], "feature_names": []}
    vector = [0.0] * len(clustering_contracts.VECTOR_FEATURE_NAMES)
    assert clustering_contracts.online_vector_update(
        vector_baseline,
        vector,
        clustering_contracts.VECTOR_FEATURE_NAMES,
    ) == clustering.online_vector_update(vector_baseline, vector, clustering.VECTOR_FEATURE_NAMES)
    assert graph_contracts.link_temporal_to_graph is not graph.link_temporal_to_graph
