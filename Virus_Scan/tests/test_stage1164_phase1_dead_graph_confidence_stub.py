import ast
from pathlib import Path


MODEL_SCORE = Path("Virus_Scan/detection/scoring/adaptive/evidence_projection.py")
FEATURE_BUNDLE = Path("Virus_Scan/detection/scoring/adaptive/feature_bundle.py")


def _module_tree():
    return ast.parse(MODEL_SCORE.read_text(encoding="utf-8"))


def test_stage1164_adaptive_scoring_has_no_dead_graph_confidence_stub():
    tree = _module_tree()
    function_names = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    }

    assert "graph_confidence" not in function_names


def test_stage1164_adaptive_scoring_uses_canonical_graph_probability_evidence():
    model_score_text = MODEL_SCORE.read_text(encoding="utf-8")
    feature_bundle_text = FEATURE_BUNDLE.read_text(encoding="utf-8")

    assert "model_graph_relationship_layer" in model_score_text
    assert "compute_graph_relationship_layer" in feature_bundle_text
    assert "p_graph_unavailable_reason" in model_score_text
    assert "return 0.5" not in model_score_text
