import ast
from pathlib import Path

from Virus_Scan.detection.api import chains_contracts
from Virus_Scan.detection.correlation.behavioral import behavior_flow
from Virus_Scan.models import markov


REPO = Path(__file__).resolve().parents[2]


def _function_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}


def test_stage1180_detection_behavior_flow_no_longer_claims_canonical_model_name():
    detection_flow_path = REPO / "Virus_Scan" / "detection" / "correlation" / "behavioral" / "behavior_flow.py"
    names = _function_names(detection_flow_path)
    assert "canonical_behavior_flow" not in names
    assert "canonical_behavior_event_name" not in names
    assert "detection_behavior_flow" in names
    assert "detection_behavior_event_name" in names


def test_stage1180_detection_public_api_exposes_detection_named_flow_only():
    assert hasattr(chains_contracts, "detection_behavior_flow")
    assert "detection_behavior_flow" in chains_contracts.__all__
    assert "canonical_behavior_flow" not in chains_contracts.__all__
    assert not hasattr(chains_contracts, "canonical_behavior_flow")


def test_stage1180_markov_canonical_behavior_flow_remains_model_owner():
    assert hasattr(markov, "canonical_behavior_flow")
    assert behavior_flow.detection_behavior_flow([
        {"tag": "api_CreateProcess"},
        {"tag": "api_CreateProcess"},
        {"tag": "tag_network_download"},
    ]) == ["createprocess", "network_download"]
    assert markov.canonical_behavior_flow([
        {"tag": "api_CreateProcess"},
        {"tag": "api_CreateProcess"},
        {"tag": "tag_network_download"},
    ]) == ("createprocess", "network_download")
