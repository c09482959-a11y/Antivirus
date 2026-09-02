
"""Stage1787 scheduler raw retry-max policy no-hook regression tests."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.context import inmemory_raw_policy_dependencies as policy
from Virus_Scan.scheduler.api.contracts import RawRangeReadError


class HostileValue:
    bool_calls = 0
    int_calls = 0
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    iter_calls = 0
    float_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.bool_calls = 0
        cls.int_calls = 0
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0

    @classmethod
    def counters(cls) -> dict[str, int]:
        return {
            "bool": cls.bool_calls,
            "int": cls.int_calls,
            "str": cls.str_calls,
            "repr": cls.repr_calls,
            "format": cls.format_calls,
            "iter": cls.iter_calls,
            "float": cls.float_calls,
        }

    def __bool__(self):  # pragma: no cover - execution is failure
        type(self).bool_calls += 1
        raise AssertionError("hostile __bool__ executed")

    def __int__(self):  # pragma: no cover
        type(self).int_calls += 1
        raise AssertionError("hostile __int__ executed")

    def __str__(self):  # pragma: no cover
        type(self).str_calls += 1
        raise AssertionError("hostile __str__ executed")

    def __repr__(self):  # pragma: no cover
        type(self).repr_calls += 1
        raise AssertionError("hostile __repr__ executed")

    def __format__(self, _spec):  # pragma: no cover
        type(self).format_calls += 1
        raise AssertionError("hostile __format__ executed")

    def __iter__(self):  # pragma: no cover
        type(self).iter_calls += 1
        raise AssertionError("hostile __iter__ executed")

    def __float__(self):  # pragma: no cover
        type(self).float_calls += 1
        raise AssertionError("hostile __float__ executed")


def test_stage1787_retry_max_rejects_hostile_runtime_value_without_hooks() -> None:
    HostileValue.reset()
    calls = []
    hostile = HostileValue()

    def record_policy_issue(where, exc, **kwargs):
        calls.append((where, type(exc).__name__, kwargs))

    assert policy.retry_max(
        runtime_value_reader=lambda *_args: hostile,
        record_policy_issue=record_policy_issue,
    ) == 1
    assert HostileValue.counters() == {
        "bool": 0,
        "int": 0,
        "str": 0,
        "repr": 0,
        "format": 0,
        "iter": 0,
        "float": 0,
    }
    assert calls and calls[0][0] == "raw_retry_max_rejected"
    assert calls[0][2]["extra"]["value_type"] == "HostileValue"


def test_stage1787_retry_max_records_runtime_failure() -> None:
    calls = []

    def fail_runtime_value(*_args):
        raise RawRangeReadError("runtime unavailable")

    def record_policy_issue(where, exc, **kwargs):
        calls.append((where, type(exc).__name__, kwargs))

    assert policy.retry_max(
        runtime_value_reader=fail_runtime_value,
        record_policy_issue=record_policy_issue,
    ) == 1
    assert calls and calls[0][0] == "raw_retry_max_unavailable"


def test_stage1787_retry_max_preserves_exact_primitive_runtime_values() -> None:
    assert policy.retry_max(runtime_value_reader=lambda *_args: "4") == 4


def test_stage1826_retry_max_rejection_uses_single_no_fallback_validation_path():
    source = read_python_file(Path("Virus_Scan/scheduler/context/inmemory_raw_policy_dependencies.py"))

    assert "scheduler_int(raw_value, fallback=1" not in source
    assert "return 1" not in source[source.index("def retry_max"):source.index("def global_raw_eligible")]


def test_stage1826_retry_max_preserves_exact_primitive_policy_values():
    assert policy.retry_max(runtime_value_reader=lambda *_args: "3") == 3
    assert policy.retry_max(runtime_value_reader=lambda *_args: 0) == 1
    assert policy.retry_max(runtime_value_reader=lambda *_args: 2.0) == 2
    assert policy.retry_max(runtime_value_reader=lambda *_args: b"4") == 4
