from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path
from types import MappingProxyType

import Virus_Scan.init_runtime as init_runtime
from Virus_Scan.init_runtime import top_level


def test_stage1008_runtime_initialization_public_manifest_exposes_names_only() -> None:
    assert init_runtime.RUNTIME_INITIALIZATION_PHASES is top_level.RUNTIME_INITIALIZATION_PHASES
    assert init_runtime.RUNTIME_INITIALIZATION_PHASES == (
        "core",
        "scheduler",
        "models",
        "detection",
        "yara",
        "scanners",
        "reporting",
    )
    assert all(isinstance(phase_name, str) for phase_name in init_runtime.RUNTIME_INITIALIZATION_PHASES)
    assert not any(callable(phase_name) for phase_name in init_runtime.RUNTIME_INITIALIZATION_PHASES)


def test_stage1008_runtime_initializers_are_private_immutable_mapping() -> None:
    mapping = top_level._RUNTIME_INITIALIZER_BY_PHASE
    assert isinstance(mapping, MappingProxyType)
    assert tuple(mapping) == init_runtime.RUNTIME_INITIALIZATION_PHASES
    assert all(callable(mapping[phase_name]) for phase_name in init_runtime.RUNTIME_INITIALIZATION_PHASES)
    try:
        mapping["core"] = object()  # type: ignore[index]
    except TypeError:
        pass
    else:  # pragma: no cover - MappingProxyType must reject mutation
        raise AssertionError("runtime initializer mapping accepted mutation")


def test_stage1008_runtime_initialization_manifest_has_no_exported_callable_tuple() -> None:
    tree = parse_python_file(Path("Virus_Scan/init_runtime/top_level.py"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "RUNTIME_INITIALIZATION_PHASES":
                    assert isinstance(node.value, ast.Tuple)
                    assert all(isinstance(elt, ast.Constant) and isinstance(elt.value, str) for elt in node.value.elts)
