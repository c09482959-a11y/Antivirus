from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.file_job_predicate import process_queue_is_file_job


class HostileQueueValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    int_calls = 0
    float_calls = 0
    getattribute_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.int_calls = 0
        cls.float_calls = 0
        cls.getattribute_calls = 0

    @classmethod
    def total_calls(cls) -> int:
        return (
            cls.str_calls
            + cls.repr_calls
            + cls.format_calls
            + cls.bool_calls
            + cls.iter_calls
            + cls.int_calls
            + cls.float_calls
            + cls.getattribute_calls
        )

    def __getattribute__(self, name: str):  # pragma: no cover - forbidden
        type(self).getattribute_calls += 1
        raise RuntimeError(name)

    def __str__(self):  # pragma: no cover - forbidden
        type(self).str_calls += 1
        raise RuntimeError("str")

    def __repr__(self):  # pragma: no cover - forbidden
        type(self).repr_calls += 1
        raise RuntimeError("repr")

    def __format__(self, spec):  # pragma: no cover - forbidden
        type(self).format_calls += 1
        raise RuntimeError("format")

    def __bool__(self):  # pragma: no cover - forbidden
        type(self).bool_calls += 1
        raise RuntimeError("bool")

    def __iter__(self):  # pragma: no cover - forbidden
        type(self).iter_calls += 1
        raise RuntimeError("iter")

    def __int__(self):  # pragma: no cover - forbidden
        type(self).int_calls += 1
        raise RuntimeError("int")

    def __float__(self):  # pragma: no cover - forbidden
        type(self).float_calls += 1
        raise RuntimeError("float")


def test_stage1881_file_job_predicate_rejects_hostile_job_type_without_hooks():
    HostileQueueValue.reset()

    assert process_queue_is_file_job({"job_type": HostileQueueValue()}) is False

    assert HostileQueueValue.total_calls() == 0


def test_stage1881_file_job_predicate_rejects_hostile_collector_without_hooks():
    HostileQueueValue.reset()

    assert process_queue_is_file_job({"job_type": "file", "collector": HostileQueueValue()}) is False

    assert HostileQueueValue.total_calls() == 0


def test_stage1881_file_job_predicate_preserves_exact_primitive_semantics():
    assert process_queue_is_file_job({"job_type": "file"}) is True
    assert process_queue_is_file_job({"job_type": "raw_stage"}) is False
    assert process_queue_is_file_job({"collector": True}) is False
    assert process_queue_is_file_job({"collector": "yes"}) is False
    assert process_queue_is_file_job({"collector": ""}) is True
    assert process_queue_is_file_job({"job_type": 0}) is True


def test_stage1881_file_job_predicate_has_no_exception_sentinel_return():
    root = Path(__file__).resolve().parents[2]
    source = root / "Virus_Scan" / "scheduler" / "queue" / "file_job_predicate.py"
    tree = parse_python_file(source)
    violations: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            for child in ast.walk(node):
                if isinstance(child, ast.Return):
                    violations.append((child.lineno, ast.unparse(child.value) if child.value else ""))
    assert violations == []
