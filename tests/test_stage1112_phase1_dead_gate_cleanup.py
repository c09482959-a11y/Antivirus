import ast
from pathlib import Path

from Virus_Scan.scanners.text_extraction import _umige_build_extraction_view
from Virus_Scan.detection.scoring.adaptive.model_score import adaptive_normalized_weights


def _tree(path: str) -> ast.AST:
    return ast.parse(Path(path).read_text(encoding="utf-8"))


def test_stage1112_targeted_dead_boolean_gates_are_removed():
    targets = {
        "Virus_Scan/scanners/text_extraction.py": "path and True",
        "Virus_Scan/scheduler/workers/inmemory_file_scan.py": "if True and",
        "Virus_Scan/models/profiles/api.py": "BULK_DEFER_PROFILE_WRITES') or False",
    }
    for path, forbidden in targets.items():
        assert forbidden not in Path(path).read_text(encoding="utf-8")


def test_stage1112_adaptive_weight_normalization_has_no_empty_dict_loop():
    tree = _tree("Virus_Scan/detection/scoring/adaptive/model_score.py")
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.For):
            iterator = node.iter
            if (
                isinstance(iterator, ast.Call)
                and isinstance(iterator.func, ast.Attribute)
                and iterator.func.attr == "items"
                and isinstance(iterator.func.value, ast.Dict)
                and not iterator.func.value.keys
            ):
                findings.append(node.lineno)
    assert findings == []


def test_stage1112_dead_gate_cleanup_preserves_extension_and_cache_behavior(tmp_path):
    view = _umige_build_extraction_view("print('hello')", tmp_path / "sample.py")
    assert "print" in view

    weights = adaptive_normalized_weights({"quick_static": 0.2, "context": 0.2})
    assert set(weights) == {"quick_static", "context"}
    assert round(sum(weights.values()), 6) == 1.0
