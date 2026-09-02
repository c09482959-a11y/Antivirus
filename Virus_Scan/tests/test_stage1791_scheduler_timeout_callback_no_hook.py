from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from Virus_Scan.scheduler.timeout.inmemory_timeout_numeric_policy import safe_timeout_policy_number
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import (
    safe_stage_is_pre_execution,
    safe_start_wait_budget,
)


RECOVERABLE = (RuntimeError, TypeError, ValueError, OSError, OverflowError)


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

    def __iter__(self) -> Iterator[object]:
        return self._hit("__iter__")

    def __repr__(self):
        return self._hit("__repr__")

    def __str__(self):
        return self._hit("__str__")


def _record():
    return {"attempt": 1, "timeout_budget": {}}


def _suppressed(_name, _exc):
    return None


def test_stage1791_start_wait_budget_rejects_hostile_return_without_hooks():
    hostile = _HookBomb()
    failures = []

    budget = safe_start_wait_budget(
        start_wait_budget=lambda _record, _default: hostile,
        job_id=1,
        record=_record(),
        default_budget=5.0,
        reason="start_wait_failed",
        pid=44,
        failures=failures,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )

    assert budget == 5.0
    assert hostile.calls == []
    assert failures[0]["reason"] == "start_wait_budget_return_rejected"


def test_stage1791_stage_classifier_rejects_hostile_truthiness_without_hooks():
    hostile = _HookBomb()
    failures = []

    pre_execution = safe_stage_is_pre_execution(
        classifier=lambda _stage: hostile,
        stage="raw",
        job_id=1,
        record=_record(),
        pid=44,
        failures=failures,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )

    assert pre_execution is False
    assert hostile.calls == []
    assert failures[0]["reason"] == "stage_pre_execution_classification_return_rejected"


def test_stage1791_timeout_policy_number_rejects_hostile_float_without_hooks():
    hostile = _HookBomb()
    failures = []

    value = safe_timeout_policy_number(
        value=hostile,
        default=9.0,
        field="heartbeat_stale_sec",
        job_id=1,
        record=_record(),
        pid=44,
        failures=failures,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )

    assert value == 9.0
    assert hostile.calls == []
    assert failures[0]["reason"] == "heartbeat_stale_sec_malformed"


def test_stage1791_timeout_architecture_blocks_raw_conversion_and_mapping_hooks():
    root = Path(__file__).resolve().parents[1]
    files = [
        root / "scheduler" / "timeout" / "inmemory_timeout_policy_callbacks.py",
        root / "scheduler" / "timeout" / "inmemory_timeout_numeric_policy.py",
    ]
    forbidden_names = {"bool", "dict", "float", "int", "repr", "str", "vars"}
    forbidden_attrs = {"get", "items", "keys", "values"}
    violations: list[tuple[str, int, str]] = []
    for file in files:
        tree = ast.parse(file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in forbidden_names:
                violations.append((file.name, node.lineno, node.func.id))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_attrs:
                violations.append((file.name, node.lineno, node.func.attr))

    assert violations == []
