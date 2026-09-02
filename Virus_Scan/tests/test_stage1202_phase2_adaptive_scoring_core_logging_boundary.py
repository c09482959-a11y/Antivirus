from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path



def _imports_for(path: str) -> tuple[str, ...]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
    return tuple(imports)


def test_adaptive_model_score_does_not_depend_on_core_logging_classification() -> None:
    imports = _imports_for("Virus_Scan/detection/scoring/adaptive/model_score.py")
    source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/model_score.py"))
    assert "Virus_Scan.core.logging" not in imports
    assert "from Virus_Scan.core.logging import classify" not in source
