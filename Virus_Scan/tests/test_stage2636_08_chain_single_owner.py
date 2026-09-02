"""Stage2636.08 canonical chain-owner and forbidden-architecture guards."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection.registries.chain_registry import CHAIN_CONCLUSION_TAGS

_REPOSITORY = Path("Virus_Scan")
_CANONICAL_REGISTRY_DEFAULTS = Path(
    "Virus_Scan/detection/registries/chain_registry_defaults.py"
)
_SUPERSEDED = (
    Path("Virus_Scan/detection/chains/execution/behavior_anchors.py"),
    Path("Virus_Scan/detection/chains/execution/explicit_anchors.py"),
    Path("Virus_Scan/detection/scoring/weighting/chain_sequence.py"),
    Path("Virus_Scan/detection/heuristics/script_execution.py"),
)
_ARCHITECTURE_FILES = (
    Path("Virus_Scan/contracts/chain_evidence.py"),
    Path("Virus_Scan/detection/chains"),
    Path("Virus_Scan/detection/registries/chain_registry.py"),
    _CANONICAL_REGISTRY_DEFAULTS,
    Path("Virus_Scan/detection/scoring/weighting/chain_bonus.py"),
    Path("Virus_Scan/detection/api/chain_evaluation.py"),
    Path("Virus_Scan/heuristics/script_exec.py"),
    Path("Virus_Scan/models/profiles/chain_state.py"),
    Path("Virus_Scan/models/profiles/chain_records.py"),
    Path("Virus_Scan/scanners/pickle/graph_base.py"),
    Path("Virus_Scan/scanners/raw_queue_scan_result.py"),
    Path("Virus_Scan/scanners/renpy.py"),
    Path("Virus_Scan/scheduler/context/inmemory_raw_dependency_factory.py"),
    Path("Virus_Scan/scheduler/workers/inmemory_raw_finalization_steps.py"),
)
_FORBIDDEN_TEXT = (
    "monkeypatch",
    "compatibility shim",
    "compatibility wrapper",
    "compatibility alias",
    "compatibility adapter",
    "parallel fallback owner",
    "fallback owner",
)


def _python_files(path: Path) -> tuple[Path, ...]:
    if path.is_file():
        return (path,)
    return tuple(
        candidate
        for candidate in sorted(path.rglob("*.py"))
        if "__pycache__" not in candidate.parts
    )


def test_chain_conclusion_identifiers_have_one_registry_owner() -> None:
    findings: list[tuple[str, int, str]] = []
    for path in _python_files(_REPOSITORY):
        if "tests" in path.parts or path == _CANONICAL_REGISTRY_DEFAULTS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and type(node.value) is str
                and node.value.strip().lower() in CHAIN_CONCLUSION_TAGS
            ):
                findings.append((path.as_posix(), node.lineno, node.value))
    assert findings == []


def test_chain_registry_and_evaluator_have_one_definition_each() -> None:
    evaluator_defs: list[tuple[str, int]] = []
    registry_defs: list[tuple[str, int]] = []
    for path in _python_files(_REPOSITORY):
        if "tests" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "evaluate_chain_evidence":
                evaluator_defs.append((path.as_posix(), node.lineno))
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
                if any(isinstance(target, ast.Name) and target.id == "CHAIN_RULE_DEFINITIONS" for target in targets):
                    registry_defs.append((path.as_posix(), node.lineno))
    assert [path for path, _line in evaluator_defs] == [
        "Virus_Scan/detection/chains/execution/anchors.py"
    ]
    assert [path for path, _line in registry_defs] == [
        "Virus_Scan/detection/registries/chain_registry_defaults.py"
    ]


def test_superseded_anchor_and_sequence_owners_are_deleted() -> None:
    assert tuple(path.as_posix() for path in _SUPERSEDED if path.exists()) == ()


def test_scanners_do_not_import_detection_to_reconstruct_chains() -> None:
    findings: list[tuple[str, int, str]] = []
    for path in _python_files(Path("Virus_Scan/scanners")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("Virus_Scan.detection"):
                findings.append((path.as_posix(), node.lineno, node.module))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("Virus_Scan.detection"):
                        findings.append((path.as_posix(), node.lineno, alias.name))
    assert findings == []


def test_chain_repair_surface_has_no_forbidden_architecture_mechanisms() -> None:
    text_findings: list[tuple[str, str]] = []
    assignment_findings: list[tuple[str, int, str]] = []
    files = tuple(
        dict.fromkeys(
            candidate
            for path in _ARCHITECTURE_FILES
            for candidate in _python_files(path)
        )
    )
    for path in files:
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        for marker in _FORBIDDEN_TEXT:
            if marker in lowered:
                text_findings.append((path.as_posix(), marker))
        tree = ast.parse(text, filename=path.as_posix())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
            for target in targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Attribute)
                    and isinstance(target.value.value, ast.Name)
                    and target.value.value.id == "sys"
                    and target.value.attr == "modules"
                ):
                    assignment_findings.append((path.as_posix(), node.lineno, "sys.modules"))
    assert text_findings == []
    assert assignment_findings == []


def test_script_execution_heuristic_has_one_canonical_owner() -> None:
    definitions: list[tuple[str, int]] = []
    for path in _python_files(_REPOSITORY):
        if "tests" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "evaluate_script_execution"
            ):
                definitions.append((path.as_posix(), node.lineno))
    assert [path for path, _line in definitions] == [
        "Virus_Scan/heuristics/script_exec.py"
    ]
