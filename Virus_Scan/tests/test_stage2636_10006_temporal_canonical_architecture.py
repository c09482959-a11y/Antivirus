"""Stage2636.10006 single-owner temporal v5 architecture regressions."""
from __future__ import annotations

import ast
from pathlib import Path


TEMPORAL_SCOPE = (
    Path("Virus_Scan/contracts/temporal_accumulator.py"),
    Path("Virus_Scan/contracts/temporal_baseline.py"),
    Path("Virus_Scan/contracts/temporal_event.py"),
    Path("Virus_Scan/contracts/temporal_learning.py"),
    Path("Virus_Scan/runtime/temporal_state.py"),
    Path("Virus_Scan/models/profiles/temporal_target.py"),
    *tuple(sorted(Path("Virus_Scan/models/temporal").glob("*.py"))),
)


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _imported_module_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            # Imported attributes are not module objects unless explicitly imported as modules.
            continue
    return names


def test_stage2636_10006_temporal_has_one_strict_v5_path_only() -> None:
    forbidden_paths = (
        Path("Virus_Scan/models/temporal/decay.py"),
        Path("Virus_Scan/models/temporal/evidence_values.py"),
        Path("Virus_Scan/runtime/temporal_state_migration.py"),
    )
    assert not any(path.exists() for path in forbidden_paths)

    combined = "\n".join(_source(path) for path in TEMPORAL_SCOPE)
    for token in (
        "TEMPORAL_EVENTS",
        "TEMPORAL_EVENT_COUNTER",
        "TEMPORAL_LAST_TIMESTAMP",
        "temporal_event_time_values",
        "temporal_overlay_reference_now",
        "record_temporal_observation",
        "temporal_state_migration",
        "compatibility shim",
        "compatibility wrapper",
        "compatibility adapter",
        "compatibility alias",
    ):
        assert token not in combined
    for version in ("_v1", "_v2", "_v3", "_v4"):
        assert version not in combined


def test_stage2636_10006_temporal_single_canonical_owners_are_unique() -> None:
    production = tuple(Path("Virus_Scan").rglob("*.py"))
    definitions = {
        "TemporalStateOwner": [],
        "TemporalLearningRequest": [],
        "TemporalEvent": [],
        "apply_temporal_baseline_learning": [],
    }
    for path in production:
        if "tests" in path.parts:
            continue
        tree = ast.parse(_source(path), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in definitions:
                    definitions[node.name].append(path.as_posix())
    assert definitions == {
        "TemporalStateOwner": ["Virus_Scan/runtime/temporal_state.py"],
        "TemporalLearningRequest": ["Virus_Scan/contracts/temporal_learning.py"],
        "TemporalEvent": ["Virus_Scan/contracts/temporal_event.py"],
        "apply_temporal_baseline_learning": ["Virus_Scan/models/temporal/dwell_baseline.py"],
    }


def test_stage2636_10006_temporal_scope_has_no_module_reassignment_or_patch_hooks() -> None:
    for path in TEMPORAL_SCOPE:
        tree = ast.parse(_source(path), filename=str(path))
        module_names = _imported_module_names(tree)
        for node in ast.walk(tree):
            targets: tuple[ast.expr, ...] = ()
            if isinstance(node, ast.Assign):
                targets = tuple(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets = (node.target,)
            elif isinstance(node, ast.AugAssign):
                targets = (node.target,)
            for target in targets:
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                    assert target.value.id not in module_names, (path, target.value.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"setattr", "delattr"}, (path, node.func.id)
        source = _source(path)
        assert "sys.modules" not in source
        assert "importlib.reload" not in source


def test_stage2636_10006_temporal_model_modules_remain_bounded() -> None:
    assert all(
        len(_source(path).splitlines()) < 300
        for path in Path("Virus_Scan/models/temporal").glob("*.py")
    )
