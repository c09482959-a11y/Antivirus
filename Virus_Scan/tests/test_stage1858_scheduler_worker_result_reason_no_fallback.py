from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.internal import worker_result_boundary
from Virus_Scan.scheduler.internal.worker_result_boundary import scheduler_reason_text
from Virus_Scan.scheduler.workers import result_contracts
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_cancel_result


class HostileReason:
    touched = False

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("reason str hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("reason repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("reason format hook executed")


class HostileReplacement(str):
    touched = False

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("replacement str hook executed")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("replacement format hook executed")


class ExplodingWorkerResult(RuntimeError):
    pass


def test_scheduler_reason_text_uses_owned_replacement_without_hostile_hooks() -> None:
    HostileReason.touched = False
    HostileReplacement.touched = False

    reason, unavailable = scheduler_reason_text(
        HostileReason(), replacement_text=HostileReplacement("hidden")  # type: ignore[arg-type]
    )

    assert reason == "scheduler_worker_result_schema_failure"
    assert unavailable == "unsafe_scheduler_worker_reason_rejected"
    assert HostileReason.touched is False
    assert HostileReplacement.touched is False


def test_scheduler_reason_text_preserves_exact_cancel_replacement() -> None:
    HostileReason.touched = False

    reason, unavailable = scheduler_reason_text(HostileReason(), replacement_text="cancelled_generation")

    assert reason == "cancelled_generation"
    assert unavailable == "unsafe_scheduler_worker_reason_rejected"
    assert HostileReason.touched is False


def test_make_scheduler_cancel_result_preserves_cancel_reason_without_formatting_hooks() -> None:
    HostileReason.touched = False

    _path, result = make_scheduler_cancel_result(HostileReason(), HostileReason())  # type: ignore[arg-type]

    assert result["scheduler_failure_reason"] == "cancelled_generation"
    assert result["cancelled_generation"] is True
    assert HostileReason.touched is False


def test_worker_result_boundary_removed_fallback_and_fstring_routes() -> None:
    boundary_source = Path(worker_result_boundary.__file__).read_text(encoding="utf-8")
    contracts_source = Path(result_contracts.__file__).read_text(encoding="utf-8")

    assert "fallback" not in boundary_source
    assert "fallback=" not in contracts_source
    for source in (boundary_source, contracts_source):
        tree = ast.parse(source)
        assert not any(isinstance(node, ast.FormattedValue) for node in ast.walk(tree))
