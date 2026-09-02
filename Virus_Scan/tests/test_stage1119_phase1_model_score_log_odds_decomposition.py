from Virus_Scan.tests.support.static_inventory import parse_python_file

import ast
from pathlib import Path


MODEL_SCORE = Path("Virus_Scan/detection/scoring/adaptive/log_odds_fusion.py")


def _tree() -> ast.Module:
    return ast.parse(MODEL_SCORE.read_text(encoding="utf-8"))


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}


def test_stage1119_log_odds_score_function_is_bounded_after_decomposition() -> None:
    functions = _functions(_tree())
    assert "calibrated_log_odds_score_100" in functions
    score_function = functions["calibrated_log_odds_score_100"]
    assert score_function.end_lineno is not None
    assert score_function.end_lineno - score_function.lineno + 1 <= 75


def test_stage1119_log_odds_helpers_preserve_canonical_metadata_sections() -> None:
    functions = _functions(_tree())
    weights_tree = parse_python_file(Path("Virus_Scan/detection/scoring/adaptive/log_odds_weights.py"))
    probabilities_tree = parse_python_file(Path("Virus_Scan/detection/scoring/adaptive/log_odds_probabilities.py"))
    functions.update(_functions(weights_tree))
    functions.update(_functions(probabilities_tree))
    expected_helpers = {
        "log_odds_learning_meta",
        "log_odds_feature_probabilities",
        "log_odds_static_model_probabilities",
        "derive_log_odds_weights",
        "apply_log_odds_concrete_caps",
        "log_odds_active_layer_bonus",
    }
    assert expected_helpers <= set(functions)
    score_source = ast.get_source_segment(MODEL_SCORE.read_text(encoding="utf-8"), functions["calibrated_log_odds_score_100"])
    assert score_source is not None
    for metadata_key in (
        "static_probability",
        "model_probability",
        "attack_chain_probability",
        "anchor_floor_hits",
        "correlation_ceiling",
        "feature_probabilities",
    ):
        assert metadata_key in score_source


def test_stage1119_model_score_keeps_static_import_ownership() -> None:
    tree = _tree()
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            parent = parents.get(node)
            while parent is not None:
                assert not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                parent = parents.get(parent)
            source = ast.get_source_segment(MODEL_SCORE.read_text(encoding="utf-8"), node) or ""
            assert "importlib" not in source
