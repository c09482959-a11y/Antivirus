from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path
from Virus_Scan.detection.tags.heuristics.runtime_library_policy import apply_detection_library_behavior_baseline
from Virus_Scan.models.profiles import apply_library_behavior_baseline



def _top_level_function_names(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}


def test_detection_runtime_library_policy_no_longer_exports_model_baseline_public_name():
    source = read_python_file(Path("Virus_Scan/detection/tags/heuristics/runtime_library_policy.py"))
    function_names = _top_level_function_names("Virus_Scan/detection/tags/heuristics/runtime_library_policy.py")

    assert "apply_library_behavior_baseline" not in function_names
    assert "apply_detection_library_behavior_baseline" in function_names
    assert '"apply_library_behavior_baseline"' not in source
    assert '"apply_detection_library_behavior_baseline"' in source


def test_detection_finalization_uses_detection_named_library_baseline_owner():
    source = read_python_file(Path("Virus_Scan/detection/tags/heuristics/finalization.py"))

    assert "apply_detection_library_behavior_baseline" in source
    assert "apply_library_behavior_baseline" not in source


def test_detection_and_model_library_baseline_owners_remain_separate_and_preserve_behavior():
    tags = ["renpy_runtime_exec", "static_anchor_proof"]
    path = "renpy/common/00library.rpy"
    strings_blob = "renpy display runtime"

    detection_result = apply_detection_library_behavior_baseline(tags, path=path, strings_blob=strings_blob)
    model_result = apply_library_behavior_baseline(tags, path=path, strings_blob=strings_blob)

    assert apply_detection_library_behavior_baseline is not apply_library_behavior_baseline
    assert "static_anchor_proof" in detection_result
    assert "static_anchor_proof" in model_result
    assert isinstance(detection_result, list)
    assert isinstance(model_result, list)
