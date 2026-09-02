from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    safe_retry_history,
    safe_retry_int,
)


class _HookBomb:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _called(self, name: str):
        self.calls.append(name)
        raise AssertionError("hostile hook called: " + name)

    def __bool__(self):
        return self._called("__bool__")

    def __format__(self, _spec):
        return self._called("__format__")

    def __int__(self):
        return self._called("__int__")

    def __iter__(self):
        return self._called("__iter__")

    def __repr__(self):
        return self._called("__repr__")

    def __str__(self):
        return self._called("__str__")

    def items(self):
        return self._called("items")


def test_stage1894_safe_retry_int_records_hostile_contract_failure_without_hooks() -> None:
    hostile = _HookBomb()
    record = {"history": ()}

    value, updated = safe_retry_int(
        value=hostile,
        replacement_value=0,
        job_id=7,
        generation=2,
        reason=hostile,
        field="attempt",
        record=record,
    )

    assert hostile.calls == []
    assert value == 0
    assert updated["retry_contract_failed"] is True
    failure = updated["retry_contract_failures"][-1]
    assert failure["field"] == "attempt"
    assert failure["error_source"] == "inmemory_retry_recovery.attempt"
    assert failure["reason"] == "<_HookBomb unsupported_retry_reason>"
    assert failure["final_json_must_record"] is True
    assert updated["history"][-1]["action"] == "retry_contract_failed"


def test_stage1894_safe_retry_history_rejects_hostile_history_without_hooks() -> None:
    hostile = _HookBomb()
    record = {"history": hostile}

    history = safe_retry_history(
        record=record,
        job_id=3,
        generation=1,
        reason="worker_exit",
    )

    assert hostile.calls == []
    assert history[-1]["action"] == "retry_contract_failed"
    failure = record["retry_contract_failures"][-1]
    assert failure["field"] == "history"
    assert failure["error_source"] == "inmemory_retry_recovery.history"
    assert "value_type=_HookBomb" in failure["detail"]


def test_stage1894_retry_contracts_source_has_no_fallback_default_or_fstrings() -> None:
    source_path = (
        Path(__file__).parents[1]
        / "scheduler"
        / "queue"
        / "inmemory_retry_contracts.py"
    )
    source = read_python_file(source_path)
    tree = parse_python_file(source_path)

    assert "fallback=" not in source
    assert "default=" not in source
    joined = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
    assert joined == []
    unsafe_keywords = []
    unsafe_args = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg in {"fallback", "default"}:
                    unsafe_keywords.append((keyword.arg, node.lineno))
        if isinstance(node, ast.FunctionDef):
            unsafe_args.extend(
                (argument.arg, node.lineno)
                for argument in node.args.args + node.args.kwonlyargs
                if argument.arg in {"fallback", "default"}
            )
    assert unsafe_keywords == []
    assert unsafe_args == []
