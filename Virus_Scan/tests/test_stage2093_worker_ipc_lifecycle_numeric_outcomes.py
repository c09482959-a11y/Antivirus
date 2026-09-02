from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.ipc_lifecycle_common import (
    worker_lifecycle_float,
    worker_lifecycle_float_outcome,
    worker_lifecycle_int,
    worker_lifecycle_int_outcome,
)


class HostileNumeric:
    touched = 0

    def __bool__(self):  # pragma: no cover - failure proves unsafe hook use
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ invoked")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __int__ invoked")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __float__ invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ invoked")


def test_stage2093_worker_lifecycle_numeric_rejections_are_typed_outcomes_without_hooks() -> None:
    HostileNumeric.touched = 0
    hostile = HostileNumeric()

    int_outcome = worker_lifecycle_int_outcome(hostile, 7)
    float_outcome = worker_lifecycle_float_outcome(hostile, 2.5)

    assert int_outcome.value == 7
    assert int_outcome.reason == "unsupported_worker_lifecycle_int"
    assert int_outcome.replacement_used is True
    assert float_outcome.value == 2.5
    assert float_outcome.reason == "unsupported_worker_lifecycle_float"
    assert float_outcome.replacement_used is True
    assert worker_lifecycle_int(hostile, 7) == 7
    assert worker_lifecycle_float(hostile, 2.5) == 2.5
    assert HostileNumeric.touched == 0


def test_stage2093_worker_lifecycle_numeric_outcomes_replay_rejection_reasons() -> None:
    assert worker_lifecycle_int_outcome(True, 3).reason == "bool_worker_lifecycle_int"
    assert worker_lifecycle_int_outcome("", 3).reason == "blank_worker_lifecycle_int"
    assert worker_lifecycle_int_outcome("+", 3).reason == "sign_only_worker_lifecycle_int"
    assert worker_lifecycle_int_outcome("1.5", 3).reason == "non_decimal_worker_lifecycle_int"
    assert worker_lifecycle_int_outcome(float("nan"), 3).reason == "non_integral_worker_lifecycle_int"
    assert worker_lifecycle_int_outcome("42", 3).value == 42
    assert worker_lifecycle_float_outcome(True, 2.5).reason == "bool_worker_lifecycle_float"
    assert worker_lifecycle_float_outcome("", 2.5).reason == "blank_worker_lifecycle_float"
    assert worker_lifecycle_float_outcome("not-a-float", 2.5).reason == "invalid_worker_lifecycle_float"
    assert worker_lifecycle_float_outcome(float("inf"), 2.5).reason == "non_finite_worker_lifecycle_float"
    assert worker_lifecycle_float_outcome("4.25", 2.5).value == 4.25


def test_stage2093_ipc_lifecycle_common_no_longer_owns_numeric_none_sentinels() -> None:
    root = Path(__file__).resolve().parents[1]
    common = (root / "scheduler" / "workers" / "ipc_lifecycle_common.py").read_text(encoding="utf-8")
    numeric = (root / "scheduler" / "workers" / "ipc_lifecycle_numeric.py").read_text(encoding="utf-8")

    assert "_parse_exact_int" not in common
    assert "_parse_exact_float" not in common
    assert "def _replacement_int" not in common
    assert "def _replacement_float" not in common
    assert "return None" not in numeric
    assert "int | None" not in numeric
    assert "float | None" not in numeric
