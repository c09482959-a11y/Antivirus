from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
import inspect
from pathlib import Path

import Virus_Scan.models.api as model_api
from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.models.profiles import baseline as profile_baseline
from Virus_Scan.models.api import profile_contracts
from Virus_Scan.routing import profile_model_projection


def _imports_for(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def test_detection_profile_snapshot_uses_public_profile_contract():
    imports = _imports_for("Virus_Scan/detection/profiles/baseline_snapshot.py")

    assert "Virus_Scan.models.profiles" not in imports
    assert "Virus_Scan.models.api.profile_contracts" in imports


def test_routing_profile_projection_uses_public_profile_contract():
    imports = _imports_for("Virus_Scan/routing/profile_model_projection.py")

    assert "Virus_Scan.models.profiles" not in imports
    assert "Virus_Scan.models.api.profile_contracts" in imports
    source = read_python_file(Path("Virus_Scan/routing/profile_model_projection.py"))
    assert " as _default_engine_profile" not in source
    assert " as _load_engine_profile" not in source
    assert profile_model_projection.default_routing_engine_profile("renpy")["engine"] == profile_contracts.default_engine_profile("renpy")["engine"]


def test_model_profile_public_contract_preserves_canonical_owner():
    assert "profile_contracts" in model_api.__all__
    assert profile_contracts.owner_get_extension_baseline is profile_api.get_extension_baseline
    assert profile_contracts.owner_default_engine_profile is profile_api.default_engine_profile
    assert profile_contracts.owner_load_engine_profile is profile_api.load_engine_profile
    assert inspect.getmodule(profile_contracts.owner_get_extension_baseline) is profile_baseline
