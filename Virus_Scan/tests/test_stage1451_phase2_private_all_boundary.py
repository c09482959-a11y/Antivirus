import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNED_ROOTS = (
    ROOT / "Virus_Scan" / "models",
    ROOT / "Virus_Scan" / "publication" / "model_evidence_projection",
    ROOT / "Virus_Scan" / "detection" / "scoring" / "adaptive",
)


def _exported_names(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
            continue
        value = ast.literal_eval(node.value)
        if isinstance(value, (tuple, list)):
            return tuple(str(item) for item in value)
    return ()


def test_stage1451_model_public_export_tuples_do_not_publish_private_names() -> None:
    offenders: dict[str, tuple[str, ...]] = {}
    for scan_root in SCANNED_ROOTS:
        for path in scan_root.rglob("*.py"):
            exported = _exported_names(path)
            private_names = tuple(name for name in exported if name.startswith("_"))
            if private_names:
                offenders[str(path.relative_to(ROOT))] = private_names

    assert offenders == {}
