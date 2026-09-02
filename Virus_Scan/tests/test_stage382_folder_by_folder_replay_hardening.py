from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
import Virus_Scan.yara.optional_dependency as optional_dependency
from pathlib import Path



def test_stage382_obsolete_generated_init_registries_are_removed():
    assert not Path("Virus_Scan/init_runtime/registry.py").exists()
    assert not Path("Virus_Scan/runtime/init_registry_names.py").exists()


def test_stage382_yara_optional_dependency_uses_direct_import_not_dynamic_import():
    source = read_python_file(Path("Virus_Scan/yara/optional_dependency.py"))
    tree = ast.parse(source)
    assert "importlib" not in source
    assert "__import__" not in source
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert not any(
        isinstance(call.func, ast.Attribute) and call.func.attr == "import_module"
        for call in calls
    )


def test_stage382_yara_dependency_boundary_imports_cleanly():
    module = optional_dependency
    dependency, error = module.yara_dependency()
    if dependency is None:
        assert error is not None
    else:
        assert error is None
        assert module.require_yara_dependency() is dependency
