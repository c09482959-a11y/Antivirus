import ast
from pathlib import Path
from types import MappingProxyType

import pytest

from Virus_Scan.runtime import runtime_flags
from Virus_Scan.runtime.runtime_flags import RuntimeFlagOwner


def test_runtime_flag_owner_defaults_coercion_and_snapshot_contract():
    owner = RuntimeFlagOwner()

    assert owner.get("missing_flag") is False
    assert owner.set("custom_truthy", value="true") is True
    assert owner.get("custom_truthy") is True
    assert owner.clear("custom_truthy") is False
    assert owner.get("custom_truthy") is False

    snapshot = owner.snapshot()
    assert isinstance(snapshot, MappingProxyType)
    assert snapshot["custom_truthy"] is False
    with pytest.raises(TypeError):
        snapshot["custom_truthy"] = True

    owner.mark("custom_truthy")
    assert owner.get("custom_truthy") is True
    assert snapshot["custom_truthy"] is False


def test_runtime_flag_owner_claim_once_is_single_transition():
    owner = RuntimeFlagOwner()

    assert owner.claim_once("download_error_logged") is True
    assert owner.claim_once("download_error_logged") is False
    assert owner.get("download_error_logged") is True
    assert owner.clear("download_error_logged") is False
    assert owner.claim_once("download_error_logged") is True


def test_runtime_flag_public_wrappers_share_single_owner_and_reset_state():
    flag_name = "stage958_runtime_flag_contract"
    runtime_flags.runtime_flag_clear(flag_name)

    try:
        assert runtime_flags.runtime_flag_get(flag_name) is False
        assert runtime_flags.runtime_flag_claim_once(flag_name) is True
        assert runtime_flags.runtime_flag_claim_once(flag_name) is False
        assert runtime_flags.runtime_flag_get(flag_name) is True
        assert runtime_flags.runtime_flag_clear(flag_name) is False
        assert runtime_flags.runtime_flag_get(flag_name) is False
    finally:
        runtime_flags.runtime_flag_clear(flag_name)


def test_runtime_flag_module_public_exports_and_static_import_boundaries():
    module_path = Path(runtime_flags.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))

    assert set(runtime_flags.__all__) == {
        "RuntimeFlagOwner",
        "runtime_flag_get",
        "runtime_flag_mark",
        "runtime_flag_clear",
        "runtime_flag_claim_once",
    }

    function_scope_imports = [
        node
        for function in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
        for node in ast.walk(function)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    assert function_scope_imports == []

    dynamic_import_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "__import__"
    ]
    assert dynamic_import_calls == []

    imported_modules = {
        alias.name
        for node in tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_modules.update(
        node.module or ""
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
    )
    assert not any(
        name.startswith((
            "Virus_Scan.scheduler",
            "Virus_Scan.detection",
            "Virus_Scan.scanners",
            "Virus_Scan.reporting",
        ))
        for name in imported_modules
    )
