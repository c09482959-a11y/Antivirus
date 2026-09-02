from __future__ import annotations

import inspect

from Virus_Scan.scheduler.internal.exact_int_text_decision import exact_int_text_decision
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    _exact_scheduler_int_text_decision,
    scheduler_int,
    scheduler_minimum_int,
)
from Virus_Scan.scheduler.workers.process_queue_worker_exit_evidence import (
    _worker_exit_int,
    _worker_exit_int_text_decision,
)


def test_scheduler_exact_integer_text_rejections_are_replayable_decisions() -> None:
    empty = _exact_scheduler_int_text_decision("")
    assert empty.accepted is False
    assert empty.value == 0
    assert empty.reason == "scheduler_integer_text_empty"

    sign_only = _exact_scheduler_int_text_decision("-")
    assert sign_only.accepted is False
    assert sign_only.reason == "scheduler_integer_text_sign_only"

    digits = _exact_scheduler_int_text_decision("12x")
    assert digits.accepted is False
    assert digits.reason == "scheduler_integer_text_digits_rejected"

    accepted = _exact_scheduler_int_text_decision("+42")
    assert accepted.accepted is True
    assert accepted.value == 42
    assert accepted.reason == ""

    assert "return None" not in inspect.getsource(_exact_scheduler_int_text_decision)


def test_scheduler_integer_public_projection_keeps_existing_defaults() -> None:
    assert scheduler_int("", default=9) == (9, "scheduler_integer_rejected")
    assert scheduler_int(b"-7", default=0) == (-7, "")
    assert scheduler_int(True, default=3) == (3, "scheduler_integer_rejected")
    assert scheduler_minimum_int("2", minimum=5) == (5, "")
    assert scheduler_minimum_int("not-int", minimum=5) == (5, "scheduler_integer_rejected")


def test_worker_exit_integer_text_rejections_are_replayable_decisions() -> None:
    empty = _worker_exit_int_text_decision("")
    assert empty.accepted is False
    assert empty.value == 0
    assert empty.reason == "worker_exit_integer_text_empty"

    sign_only = _worker_exit_int_text_decision("+")
    assert sign_only.accepted is False
    assert sign_only.reason == "worker_exit_integer_text_sign_only"

    digits = _worker_exit_int_text_decision("7.1")
    assert digits.accepted is False
    assert digits.reason == "worker_exit_integer_text_digits_rejected"

    accepted = _worker_exit_int_text_decision("-11")
    assert accepted.accepted is True
    assert accepted.value == -11
    assert accepted.reason == ""

    assert "return None" not in inspect.getsource(_worker_exit_int_text_decision)


def test_worker_exit_integer_public_projection_keeps_existing_defaults() -> None:
    assert _worker_exit_int("", 4) == (4, "worker_exit_integer_rejected")
    assert _worker_exit_int(bytearray(b"+12"), 0) == (12, "")
    assert _worker_exit_int(False, 8) == (8, "worker_exit_integer_rejected")


def test_shared_exact_integer_decision_records_normalized_text() -> None:
    decision = exact_int_text_decision(
        " 001 ",
        empty_reason="empty",
        sign_only_reason="sign",
        digit_reason="digit",
    )
    assert decision.accepted is True
    assert decision.value == 1
    assert decision.normalized_text == "001"
