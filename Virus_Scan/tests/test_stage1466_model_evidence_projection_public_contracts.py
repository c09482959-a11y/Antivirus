from __future__ import annotations

import ast
from pathlib import Path

PROJECTION_ROOT = Path("Virus_Scan/publication/model_evidence_projection")


def _module_tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def test_stage1466_model_evidence_projection_uses_public_in_package_imports() -> None:
    offenders: list[str] = []
    for path in sorted(PROJECTION_ROOT.glob("*.py")):
        tree = _module_tree(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if not (node.level and node.module):
                continue
            for alias in node.names:
                if alias.name.startswith("_") and not alias.name.startswith("__"):
                    offenders.append(f"{path}:{node.lineno}:{node.module}:{alias.name}")
    assert offenders == []


def test_stage1466_model_evidence_projection_public_exports_are_not_private() -> None:
    offenders: list[str] = []
    for path in sorted(PROJECTION_ROOT.glob("*.py")):
        tree = _module_tree(path)
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
                continue
            exported = ast.literal_eval(node.value)
            for name in exported:
                if name.startswith("_") and not name.startswith("__"):
                    offenders.append(f"{path}:{node.lineno}:{name}")
    assert offenders == []


def test_stage1466_model_evidence_projection_api_keeps_public_delegate_name() -> None:
    api_tree = _module_tree(PROJECTION_ROOT / "api.py")
    imports = [node for node in ast.walk(api_tree) if isinstance(node, ast.ImportFrom)]
    assert any(
        alias.name == "build_model_evidence_final_json_fields"
        and alias.asname == "assemble_model_evidence_final_json_fields"
        for node in imports
        for alias in node.names
    )
    assert not any(
        alias.asname and alias.asname.startswith("_")
        for node in imports
        for alias in node.names
    )
