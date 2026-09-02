from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.inmemory_lifecycle_contracts import lifecycle_transition_snapshot


class _HookBomb:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _hit(self, name: str):
        self.calls.append(name)
        raise AssertionError(name)

    def __bool__(self):
        return self._hit("__bool__")

    def __float__(self):
        return self._hit("__float__")

    def __format__(self, _spec):
        return self._hit("__format__")

    def __int__(self):
        return self._hit("__int__")

    def __iter__(self):
        return self._hit("__iter__")

    def __repr__(self):
        return self._hit("__repr__")

    def __str__(self):
        return self._hit("__str__")


def _module_tree(name: str) -> ast.AST:
    root = Path(__file__).resolve().parents[1]
    return parse_python_file(root / "scheduler" / "queue" / name)


def test_stage1889_lifecycle_required_fields_reject_hostile_values_without_hooks() -> None:
    hostile = _HookBomb()

    snapshot, rejections = lifecycle_transition_snapshot(
        {
            "epoch": hostile,
            "sequence": hostile,
            "job_id": hostile,
            "attempt": hostile,
            "transition": hostile,
        }
    )

    assert hostile.calls == []
    assert snapshot is not None
    assert snapshot["epoch"] == 0
    assert snapshot["sequence"] == 0
    assert snapshot["job_id"] == -1
    assert snapshot["attempt"] == 0
    assert snapshot["transition"] == ""
    reasons = {entry["reason"] for entry in rejections}
    assert {
        "lifecycle_epoch_rejected",
        "lifecycle_sequence_rejected",
        "lifecycle_job_id_rejected",
        "lifecycle_attempt_rejected",
        "lifecycle_transition_rejected",
    } <= reasons


def test_stage1889_lifecycle_contracts_have_no_dynamic_reason_formatting_or_fallback_keywords() -> None:
    tree = _module_tree("inmemory_lifecycle_contracts.py")
    violations: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            violations.append((node.lineno, "f_string"))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"scheduler_int", "scheduler_float", "scheduler_text"}:
                for keyword in node.keywords:
                    if keyword.arg == "fallback":
                        violations.append((node.lineno, "fallback_keyword"))
    assert violations == []


def test_stage1889_lifecycle_reason_selector_has_no_top_level_mutable_policy_map() -> None:
    tree = _module_tree("inmemory_lifecycle_reasons.py")
    assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree))
    mutable_assignments: list[tuple[int, str]] = []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value if isinstance(node, ast.AnnAssign) else node.value
            if isinstance(value, (ast.Dict, ast.List, ast.Set)):
                mutable_assignments.append((node.lineno, type(value).__name__))
    assert mutable_assignments == []
