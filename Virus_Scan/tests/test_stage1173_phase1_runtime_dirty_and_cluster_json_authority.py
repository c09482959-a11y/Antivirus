from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.runtime.model_state import mark_runtime_models_dirty
from Virus_Scan.runtime.runtime_flags import runtime_flag_clear, runtime_flag_get
from Virus_Scan.runtime.cluster_state import (
    RuntimeClusterState,
    configure_runtime_cluster_state,
    runtime_cluster_state_to_json,
)
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster


def test_stage1173_runtime_model_dirty_marker_is_runtime_owned() -> None:
    markov_source = "\n".join(path.read_text(encoding="utf-8") for path in Path("Virus_Scan/models/markov").glob("*.py"))
    profiles_source = read_python_file(Path("Virus_Scan/models/profiles/api.py"))
    temporal_source = "\n".join(path.read_text(encoding="utf-8") for path in Path("Virus_Scan/models/temporal").glob("*.py"))
    replay_source = "\n".join(path.read_text(encoding="utf-8") for path in Path("Virus_Scan/models/replay").glob("*.py"))

    for source in (markov_source, profiles_source):
        tree = ast.parse(source)
        assert "mark_runtime_models_dirty" not in {
            node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        }

    assert "runtime_model_state.mark_runtime_models_dirty()" in temporal_source
    assert "runtime_model_state.mark_runtime_models_dirty()" not in replay_source
    assert "learning_result" in replay_source
    assert "model_updates_authorized" in replay_source
    assert "def mark_runtime_models_dirty" not in temporal_source
    assert "def mark_runtime_models_dirty" not in replay_source

    runtime_flag_clear("runtime_model_state_dirty")
    assert runtime_flag_get("runtime_model_state_dirty") is False
    mark_runtime_models_dirty()
    assert runtime_flag_get("runtime_model_state_dirty") is True


def test_stage1173_cluster_json_serializer_is_runtime_owned() -> None:
    clustering_source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(Path("Virus_Scan/models/clustering").glob("*.py")))
    assert "def _runtime_cluster_state_to_json" not in clustering_source
    assert "def _json_safe_cluster_meta" not in clustering_source

    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    seed_canonical_microcluster(
        state, "cluster-b", members=("private-node-1",), kind="mixed",
        tags=("b", "a"), confidence=0.6, malicious_ratio=0.2,
        trusted_sample_count=3,
    )

    snapshot = runtime_cluster_state_to_json()
    assert snapshot["schema"] == "online_microcluster_state_v2"
    assert "cluster_signatures" not in snapshot
    assert snapshot["microclusters"]["cluster-b"]["tag_signature"] == ["a", "b"]
    assert snapshot["microclusters"]["cluster-b"]["members"] == ["private-node-1"]
