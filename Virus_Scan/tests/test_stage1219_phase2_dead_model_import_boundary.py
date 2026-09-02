from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path



def _imported_modules(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.add(str(node.module or ""))
        elif isinstance(node, ast.Import):
            modules.update(str(alias.name) for alias in node.names)
    return modules


def test_extension_router_does_not_keep_dead_profile_model_import() -> None:
    imports = _imported_modules("Virus_Scan/routing/extensions.py")
    assert "Virus_Scan.models.profiles" not in imports


def test_engine_detect_does_not_keep_dead_flush_or_retention_model_imports() -> None:
    source = read_python_file(Path("Virus_Scan/routing/engine_detect.py"))
    assert "flush_profile_writes" not in source
    assert "prune_engine_profile_for_retention" not in source
