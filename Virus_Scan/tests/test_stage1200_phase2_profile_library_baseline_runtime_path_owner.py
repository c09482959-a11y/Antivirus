from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path

from Virus_Scan.contracts.library_baseline import library_behavior_baseline_profile
from Virus_Scan.models import profiles



def _imports_for(path: str) -> tuple[str, ...]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
    return tuple(imports)


def test_profile_model_no_longer_imports_core_paths_for_baseline_or_runtime_root() -> None:
    imports = _imports_for("Virus_Scan/models/profiles/baseline.py")
    assert "Virus_Scan.core.paths" not in imports
    assert "Virus_Scan.contracts.library_baseline" in imports
    assert "Virus_Scan.runtime.resource_paths" not in imports


def test_library_baseline_profile_contract_preserves_runtime_binary_profile() -> None:
    profile = library_behavior_baseline_profile("/game/Managed/UnityPlayer.dll", "")
    assert profile is not None
    assert profile["name"] == "runtime_engine_binary"
    assert "engine_runtime_library" in profile["identity_tags"]
    assert "dll_load" in profile["normal_tags"]


def test_profile_model_consumes_contract_profile_function() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/baseline.py"))
    assert "library_behavior_baseline_profile(path, strings_blob)" in source
    assert "get_library_behavior_baseline_profile" not in source
    assert not hasattr(profiles, "library_behavior_baseline_profile")
