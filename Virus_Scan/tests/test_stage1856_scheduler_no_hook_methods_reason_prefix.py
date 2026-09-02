from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.internal import no_hook_methods
from Virus_Scan.scheduler.internal.no_hook_methods import (
    safe_scheduler_bound_method,
    safe_scheduler_instance_callable,
)


class HostilePrefix:
    touched = False

    def __str__(self):  # pragma: no cover - must not execute
        HostilePrefix.touched = True
        raise AssertionError("str hook executed")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        HostilePrefix.touched = True
        raise AssertionError("format hook executed")


class HostileGetAttribute:
    def __getattribute__(self, name):  # pragma: no cover - must not execute
        raise AssertionError(name)


class PlainCallableOwner:
    def __init__(self) -> None:
        self.callback = lambda: "owned"


def test_safe_bound_method_rejects_hostile_prefix_without_format_or_str_hooks() -> None:
    HostilePrefix.touched = False
    method, reason = safe_scheduler_bound_method(
        HostileGetAttribute(),
        "close",
        reason_prefix=HostilePrefix(),  # type: ignore[arg-type]
    )
    assert method is None
    assert reason == "unsafe_scheduler_method_getattribute_rejected"
    assert HostilePrefix.touched is False


def test_safe_instance_callable_rejects_hostile_prefix_without_format_or_str_hooks() -> None:
    HostilePrefix.touched = False
    callback, reason = safe_scheduler_instance_callable(
        PlainCallableOwner(),
        "missing",
        reason_prefix=HostilePrefix(),  # type: ignore[arg-type]
    )
    assert callback is None
    assert reason == "unsafe_scheduler_callable_missing"
    assert HostilePrefix.touched is False


def test_safe_instance_callable_preserves_exact_owned_prefix_and_callable_lookup() -> None:
    callback, reason = safe_scheduler_instance_callable(
        PlainCallableOwner(),
        "callback",
        reason_prefix="owned_callable",
    )
    assert reason == ""
    assert callback() == "owned"

    callback, reason = safe_scheduler_instance_callable(
        PlainCallableOwner(),
        "missing",
        reason_prefix="owned_callable",
    )
    assert callback is None
    assert reason == "owned_callable_missing"


def test_no_hook_methods_does_not_format_reason_prefix() -> None:
    source = Path(no_hook_methods.__file__).read_text(encoding="utf-8")
    assert 'f"{reason_prefix}' not in source
    assert "f'{reason_prefix}" not in source
    tree = ast.parse(source)
    assert not any(isinstance(node, ast.FormattedValue) for node in ast.walk(tree))
