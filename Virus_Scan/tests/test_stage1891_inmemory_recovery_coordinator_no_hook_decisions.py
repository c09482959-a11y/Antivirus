from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.inmemory_empty_drain import InMemoryEmptyDrainRecoveryDecision
from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import (
    _cancel_stall_poison_mask,
    _empty_drain_delta_evidence_and_result,
    _retry_decision_delta_and_evidence,
)
from Virus_Scan.scheduler.queue.inmemory_retry_contracts import InMemoryRetryDecision


class _HostileDecision:
    def __init__(self) -> None:
        object.__setattr__(self, "calls", [])

    def _hit(self, name: str):
        object.__getattribute__(self, "calls").append(name)
        raise AssertionError(name)

    def __getattribute__(self, name: str):
        if name in {"calls", "_hit"}:
            return object.__getattribute__(self, name)
        return self._hit("__getattribute__:" + name)

    def __bool__(self):
        return self._hit("__bool__")

    def __int__(self):
        return self._hit("__int__")

    def __iter__(self):
        return self._hit("__iter__")

    def __repr__(self):
        return self._hit("__repr__")

    def __str__(self):
        return self._hit("__str__")


def _coordinator_tree() -> ast.AST:
    root = Path(__file__).resolve().parents[1]
    return parse_python_file(root / "scheduler" / "queue" / "inmemory_recovery_coordinator.py")


def test_stage1891_retry_decision_projection_rejects_hostile_decision_without_hooks() -> None:
    hostile = _HostileDecision()

    assert _retry_decision_delta_and_evidence(hostile) == (0, ())

    assert hostile.calls == []


def test_stage1891_empty_drain_projection_rejects_hostile_decision_without_hooks() -> None:
    hostile = _HostileDecision()

    assert _empty_drain_delta_evidence_and_result(hostile) == (0, (), (0, 0))

    assert hostile.calls == []


def test_stage1891_cancel_stall_mask_rejects_hostile_value_without_int_hook() -> None:
    hostile = _HostileDecision()

    assert _cancel_stall_poison_mask(hostile) == 0

    assert hostile.calls == []


def test_stage1891_decision_projection_preserves_exact_contract_values() -> None:
    retry = InMemoryRetryDecision(True, 2, ({"stage": "retry"},))
    empty = InMemoryEmptyDrainRecoveryDecision(1, 3, 4, ({"stage": "empty"},))

    assert _retry_decision_delta_and_evidence(retry) == (2, ({"stage": "retry"},))
    assert _empty_drain_delta_evidence_and_result(empty) == (4, ({"stage": "empty"},), (1, 3))


def test_stage1891_recovery_coordinator_has_no_dynamic_decision_materialization_paths() -> None:
    violations: list[tuple[int, str]] = []
    for node in ast.walk(_coordinator_tree()):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"int", "getattr"}:
            violations.append((node.lineno, node.func.id))
        if isinstance(node, ast.Attribute) and node.attr in {"completed_delta", "evidence"}:
            parent = getattr(node, "parent", None)
            if parent is not None and isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) and parent.func.id in {"int", "getattr"}:
                violations.append((node.lineno, node.attr))
    assert violations == []
