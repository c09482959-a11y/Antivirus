from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path
from types import MappingProxyType

import pytest

import Virus_Scan.init_runtime as init_runtime
from Virus_Scan.init_runtime import top_level
from Virus_Scan.runtime.lifecycle_state import RuntimeLifecycleState


def test_stage951_init_runtime_exports_canonical_top_level_contracts() -> None:
    assert init_runtime.run_top_level_init is top_level.run_top_level_init
    assert init_runtime.RUNTIME_INITIALIZATION_PHASES is top_level.RUNTIME_INITIALIZATION_PHASES
    assert tuple(init_runtime.__all__) == ("RUNTIME_INITIALIZATION_PHASES", "run_top_level_init")

    phase_names = tuple(init_runtime.RUNTIME_INITIALIZATION_PHASES)
    assert phase_names == (
        "core",
        "scheduler",
        "models",
        "detection",
        "yara",
        "scanners",
        "reporting",
    )
    assert len(set(phase_names)) == len(phase_names)
    assert all(isinstance(phase_name, str) for phase_name in init_runtime.RUNTIME_INITIALIZATION_PHASES)
    assert not any(callable(phase_name) for phase_name in init_runtime.RUNTIME_INITIALIZATION_PHASES)


def test_stage951_top_level_init_uses_static_module_level_phase_ownership() -> None:
    tree = parse_python_file(Path("Virus_Scan/init_runtime/top_level.py"))
    function_scope_imports: list[ast.AST] = []
    phase_assignment_names: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_scope_imports.extend(
                child for child in ast.walk(node) if isinstance(child, (ast.Import, ast.ImportFrom))
            )
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "RUNTIME_INITIALIZATION_PHASES":
                    for elt in getattr(node.value, "elts", []):
                        if isinstance(elt, ast.Constant):
                            phase_assignment_names.append(str(elt.value))

    assert function_scope_imports == []
    assert tuple(phase_assignment_names) == tuple(top_level.RUNTIME_INITIALIZATION_PHASES)


def test_stage951_lifecycle_snapshot_is_immutable_and_preserves_legacy_aliases() -> None:
    state = RuntimeLifecycleState()
    state.mark_bootstrap_registration_validated(7)
    state.mark_dependency_providers_registered()
    state.mark_initialized()
    snapshot = state.snapshot()

    assert isinstance(snapshot, MappingProxyType)
    assert snapshot["initialized"] is True
    assert snapshot["_INITIALIZED"] is True
    assert snapshot["bootstrap_registration_module_count"] == 7
    assert snapshot["BOOTSTRAP_REGISTRATION_MODULE_COUNT"] == 7
    assert snapshot["bootstrap_registration_validated"] is True
    assert snapshot["BOOTSTRAP_REGISTRATION_VALIDATED"] is True
    assert snapshot["dependency_providers_registered"] is True
    assert snapshot["BOOTSTRAP_DEPENDENCY_PROVIDERS_REGISTERED"] is True
    assert snapshot["phases_completed"] == ()
    assert snapshot["_TOP_LEVEL_INIT_PHASES_COMPLETED"] == ()

    with pytest.raises(TypeError):
        snapshot["initialized"] = False  # type: ignore[index]
    assert isinstance(snapshot["phases_completed"], tuple)


def test_stage951_lifecycle_top_level_flow_is_ordered_and_reentry_guarded() -> None:
    state = RuntimeLifecycleState()

    state.begin_top_level()
    state.complete_phase("core")
    state.complete_phase("scheduler")
    active = state.snapshot()
    assert active["top_level_initializing"] is True
    assert active["_TOP_LEVEL_INITIALIZING"] is True
    assert active["phases_completed"] == ("core", "scheduler")
    assert active["_TOP_LEVEL_INIT_PHASES_COMPLETED"] == ("core", "scheduler")

    with pytest.raises(RuntimeError, match="re-entered"):
        state.begin_top_level()

    state.finish_top_level()
    finished = state.snapshot()
    assert finished["top_level_initialized"] is True
    assert finished["_TOP_LEVEL_INITIALIZED"] is True
    assert finished["top_level_initializing"] is False
    assert finished["phases_completed"] == ("core", "scheduler")

    state.begin_top_level()
    assert state.snapshot()["phases_completed"] == ("core", "scheduler")


def test_stage951_lifecycle_failure_clears_in_progress_without_erasing_phase_evidence() -> None:
    state = RuntimeLifecycleState()
    state.begin_top_level()
    state.complete_phase("core")
    state.fail_top_level()
    failed = state.snapshot()

    assert failed["top_level_initialized"] is False
    assert failed["top_level_initializing"] is False
    assert failed["phases_completed"] == ("core",)

    state.begin_top_level()
    restarted = state.snapshot()
    assert restarted["top_level_initializing"] is True
    assert restarted["phases_completed"] == ()
