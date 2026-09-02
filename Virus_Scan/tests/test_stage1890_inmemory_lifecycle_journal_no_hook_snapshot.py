from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.inmemory_lifecycle_journal import InMemoryLifecycleJournal
from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest


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


class _HostileEvent:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _hit(self, name: str):
        self.calls.append(name)
        raise AssertionError(name)

    def items(self):
        return self._hit("items")

    def __iter__(self):
        return self._hit("__iter__")

    def __repr__(self):
        return self._hit("__repr__")

    def __str__(self):
        return self._hit("__str__")


def _journal_tree() -> ast.AST:
    root = Path(__file__).resolve().parents[1]
    return parse_python_file(root / "scheduler" / "queue" / "inmemory_lifecycle_journal.py")


def test_stage1890_lifecycle_journal_record_rejects_hostile_pid_without_bool_hook() -> None:
    hostile = _HookBomb()
    journal = InMemoryLifecycleJournal(epoch=1)

    item = journal.record_request(
        InMemoryLifecycleRecordRequest(
            job_id=1,
            attempt=1,
            transition="queued",
            worker_pid=hostile,
        )
    )

    assert hostile.calls == []
    assert item.worker_pid == 0


def test_stage1890_lifecycle_journal_snapshot_rejects_hostile_event_without_items_hook() -> None:
    hostile = _HostileEvent()
    journal = InMemoryLifecycleJournal(epoch=1)
    journal._events.append(hostile)

    snapshot = journal.snapshot()

    assert hostile.calls == []
    assert snapshot == ((("event_type", "_HostileEvent"), ("lifecycle_event_rejected", True), ("reason", "lifecycle_event_mapping_rejected")),)


def test_stage1890_lifecycle_journal_snapshot_keeps_canonical_static_field_order() -> None:
    journal = InMemoryLifecycleJournal(epoch=7)
    journal.record_request(
        InMemoryLifecycleRecordRequest(
            job_id=3,
            attempt=2,
            transition="queued",
            worker_pid=11,
            reason="unit",
            state="queued",
        )
    )

    snapshot = journal.snapshot()

    assert snapshot == (
        (
            ("attempt", 2),
            ("epoch", 7),
            ("job_id", 3),
            ("monotonic_ns", snapshot[0][3][1]),
            ("reason", "unit"),
            ("sequence", 1),
            ("state", "queued"),
            ("timestamp", snapshot[0][7][1]),
            ("transition", "queued"),
            ("worker_pid", 11),
        ),
    )


def test_stage1890_lifecycle_journal_exposes_only_request_append_owner() -> None:
    method_names = {
        node.name
        for node in ast.walk(_journal_tree())
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "record_request" in method_names
    assert "record" not in method_names


def test_stage1890_lifecycle_journal_has_no_items_sorted_or_boolop_snapshot_paths() -> None:
    violations: list[tuple[int, str]] = []
    for node in ast.walk(_journal_tree()):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "sorted":
            violations.append((node.lineno, "sorted"))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "items":
            violations.append((node.lineno, "items"))
        if isinstance(node, ast.BoolOp):
            violations.append((node.lineno, "boolop"))
        if isinstance(node, ast.JoinedStr):
            violations.append((node.lineno, "f_string"))
    assert violations == []
