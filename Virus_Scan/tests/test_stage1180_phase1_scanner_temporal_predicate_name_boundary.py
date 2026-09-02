import ast
from pathlib import Path

from Virus_Scan.models.temporal import anomaly as temporal_anomaly
from Virus_Scan.scanners import binary_behavior
from Virus_Scan.scanners import binary
from Virus_Scan.scanners import binary_behavior_predicates


REPO = Path(__file__).resolve().parents[2]


def _function_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}


def test_stage1180_temporal_delayed_execution_authority_stays_in_model_layer():
    scanner_predicates = REPO / "Virus_Scan" / "scanners" / "binary_behavior_predicates.py"
    assert "_temporal_delayed_execution_score" not in _function_names(scanner_predicates)
    assert not hasattr(temporal_anomaly, "temporal_delayed_execution_score")


def test_stage1180_binary_scanner_keeps_binary_named_delayed_execution_predicate():
    score, hits = binary_behavior_predicates._binary_delayed_execution_score([
        {"tag": "anti_sandbox_sleep"},
        {"tag": "powershell_exec"},
    ])
    assert score == 4.0
    assert hits == ["temporal_delayed_execution"]


def test_stage1180_binary_scanner_public_surface_uses_binary_name():
    assert hasattr(binary_behavior, "_binary_delayed_execution_score")
    assert not hasattr(binary, "_binary_delayed_execution_score")
    assert not hasattr(binary_behavior, "_temporal_delayed_execution_score")
    assert not hasattr(binary, "_temporal_delayed_execution_score")
