import ast
from pathlib import Path


def test_layered_detection_scoring_has_one_canonical_owner():
    repo = Path(__file__).resolve().parents[2]
    owners = []
    for path in (repo / "Virus_Scan").rglob("*.py"):
        if "__pycache__" in path.parts or "tests" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(isinstance(node, ast.FunctionDef) and node.name == "compute_layered_detection" for node in tree.body):
            owners.append(path.relative_to(repo).as_posix())
    assert owners == ["Virus_Scan/detection/scoring/full_analysis/layered_score.py"]
