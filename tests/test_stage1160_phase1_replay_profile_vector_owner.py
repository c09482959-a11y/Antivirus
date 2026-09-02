from pathlib import Path
import ast

from Virus_Scan.models.replay.api import result_learning_payload


def _imports_for(path: str):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    return [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]


def test_stage1160_replay_uses_profile_owned_raw_flow_contract_only():
    imports = _imports_for("Virus_Scan/models/replay/payload.py")
    assert not any((node.module or "") == "Virus_Scan.detection.api.model_behavior_contracts" for node in imports)
    assert not any((node.module or "") == "Virus_Scan.models.profiles" for node in imports)
    profile_contract_imports = [
        node for node in imports if (node.module or "") == "Virus_Scan.models.api.profile_learning_contracts"
    ]
    imported_names = {alias.name for node in profile_contract_imports for alias in node.names}
    assert imported_names == {"canonical_behavior_flow_from_sources"}
    assert "behavior_vector_from_scan" not in imported_names


def test_stage1160_replay_learning_payload_carries_raw_facts_not_a_vector():
    result = {
        "file": "sample.py",
        "classification": "benign_clean",
        "tags": ["process_exec", "network_fetch"],
        "yara_hits": ["ExampleRule"],
        "score": 12.0,
        "engine_context": {"other": 1.0},
        "ordered_events": ["process_exec", "network_fetch"],
        "scan_integrity": {"allow_learning": True},
        "feature_vector": [9.9],
    }
    payload = result_learning_payload(result)
    assert payload is not None
    assert payload["file_path"] == "sample.py"
    assert payload["behavior_flow"] == ["process_exec", "network_fetch"]
    assert "vector" not in payload
