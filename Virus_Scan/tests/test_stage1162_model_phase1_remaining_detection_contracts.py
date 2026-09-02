from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models.clustering import build_feature_vector
from Virus_Scan.models.clustering import VECTOR_FEATURE_NAMES
from Virus_Scan.runtime.profile_scoring_state import ProfileScoringState
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state


def _imports_from(path: str):
    source_path = Path(path)
    source = "\n".join(p.read_text(encoding="utf-8") for p in sorted(source_path.glob("*.py"))) if source_path.is_dir() else source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=path)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            out.append(node.module)
    return out


def test_stage1162_clustering_no_longer_imports_detection_yara_api_contract() -> None:
    imports = _imports_from("Virus_Scan/models/clustering")
    assert "Virus_Scan.detection.api.yara_model_contracts" not in imports
    assert all(not module.startswith("Virus_Scan.detection.api.yara") for module in imports)


def test_stage1162_clustering_vector_excludes_generic_yara_features() -> None:
    configure_runtime_cluster_state(RuntimeClusterState())
    vector = build_feature_vector(
        "sample.bin",
        ["process_exec"],
        {"risk": 0.0, "anomaly": 0.0},
        {"belief": 0.0},
        {"transition": 0.0, "rarity": 0.0, "pair_anomaly": 0.0},
        {"other": 1.0},
    )
    assert "yara_count" not in VECTOR_FEATURE_NAMES
    assert "yara_weight" not in VECTOR_FEATURE_NAMES
    assert len(vector) == len(VECTOR_FEATURE_NAMES)


def test_stage1162_profile_scoring_state_is_runtime_owned_snapshot_contract() -> None:
    imports = _imports_from("Virus_Scan/models/profiles/api.py")
    assert "Virus_Scan.runtime.profile_scoring_state" in imports
    assert "Virus_Scan.models.profile_state" not in imports
    assert "Virus_Scan.contracts.tag_evidence" not in imports
    assert "Virus_Scan.detection.api.profile_model_contracts" not in imports
    assert "Virus_Scan.detection.tags.heuristics.dangerous_anchors" not in imports
    assert "Virus_Scan.detection.evidence.policy" not in imports
    assert not Path("Virus_Scan/detection/scoring/profile_state.py").exists()
    state = ProfileScoringState()
    source = {"renpy": {"weights": {"tag": [1.0]}}}
    detached = state.freeze(source)
    source["renpy"]["weights"]["tag"].append(99.0)
    detached["renpy"]["weights"]["tag"].append(42.0)
    assert state.get_profile("renpy") == {"weights": {"tag": [1.0]}}


def test_stage1162_removed_stale_detection_api_wrappers() -> None:
    assert not Path("Virus_Scan/detection/api/yara_model_contracts.py").exists()
    assert not Path("Virus_Scan/detection/api/profile_model_contracts.py").exists()
