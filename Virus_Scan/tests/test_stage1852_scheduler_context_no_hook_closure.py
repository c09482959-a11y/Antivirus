from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.internal.context_no_hook import (
    context_float,
    context_int,
    context_text_tuple,
)


ROOT = Path(__file__).resolve().parents[1]
CONTEXT_SOURCE = ROOT / "scheduler" / "internal" / "context_no_hook.py"


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    getattribute_calls = 0

    def __getattribute__(self, name):
        if name == "__class__":
            type(self).getattribute_calls += 1
            raise AssertionError("__class__ hook must not execute")
        return object.__getattribute__(self, name)

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("__str__ hook must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("__repr__ hook must not execute")

    def __format__(self, _spec):
        type(self).format_calls += 1
        raise AssertionError("__format__ hook must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("__bool__ hook must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise AssertionError("__iter__ hook must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise AssertionError("__float__ hook must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise AssertionError("__int__ hook must not execute")


def _reset_hooks() -> None:
    HostileValue.str_calls = 0
    HostileValue.repr_calls = 0
    HostileValue.format_calls = 0
    HostileValue.bool_calls = 0
    HostileValue.iter_calls = 0
    HostileValue.float_calls = 0
    HostileValue.int_calls = 0
    HostileValue.getattribute_calls = 0


def _assert_no_hooks() -> None:
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.getattribute_calls == 0


def test_stage1852_context_int_and_float_preserve_exact_primitive_behavior() -> None:
    assert context_int("7", field_name="workers", default=1, minimum=1) == (7, ())
    assert context_int(0, field_name="workers", default=1, minimum=1) == (1, ())
    assert context_float("2.5", field_name="timeout", default=1.0, minimum=0.0) == (2.5, ())
    assert context_float(-1.0, field_name="timeout", default=1.0, minimum=0.0) == (0.0, ())


def test_stage1852_context_numeric_boundaries_reject_hostile_values_without_hooks() -> None:
    _reset_hooks()
    hostile = HostileValue()

    int_value, int_evidence = context_int(hostile, field_name="workers", default=3, minimum=1)
    float_value, float_evidence = context_float(hostile, field_name="timeout", default=4.0, minimum=0.0)

    assert int_value == 3
    assert int_evidence[0]["reason"] == "unsupported_scheduler_context_int"
    assert float_value == 4.0
    assert float_evidence[0]["reason"] == "unsupported_scheduler_context_float"
    _assert_no_hooks()


def test_stage1852_context_text_tuple_uses_owned_indexed_field_names_without_fstrings() -> None:
    _reset_hooks()
    hostile = HostileValue()

    values, evidence = context_text_tuple(("alpha", hostile), field_name="binding")

    assert values == ("alpha",)
    assert evidence[0]["field_name"] == "binding_1"
    assert evidence[0]["reason"] == "unsupported_scheduler_context_text"
    _assert_no_hooks()


def test_stage1852_context_source_forbids_reopened_fallback_and_index_fstring_patterns() -> None:
    source = CONTEXT_SOURCE.read_text(encoding="utf-8")
    forbidden = (
        "fallback=default",
        'field_name=f"{field_name}_{index}"',
        'context_text(item, field_name=f"{field_name}_{index}", default="")',
    )
    for snippet in forbidden:
        assert snippet not in source
