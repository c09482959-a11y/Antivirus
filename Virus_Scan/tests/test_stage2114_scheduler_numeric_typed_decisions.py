from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.evidence.scheduler_json_writer_support import (
    _exact_int_text_decision as raw_policy_exact_int_text_decision,
    raw_policy_int,
)
from Virus_Scan.scheduler.execution.scheduler_file_message_support import (
    _exact_metric_decision,
    scheduler_slow_file_message,
)
from Virus_Scan.scheduler.internal.context_numeric_support import (
    _exact_context_int_text_decision,
    parse_context_int,
)
from Virus_Scan.scheduler.workers.no_hook_scalars import (
    _int_text_decision,
    worker_int,
)


class HostileNumeric:
    touched = 0

    def __bool__(self):  # pragma: no cover - invoked hook is the failure
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ must not run")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __int__ must not run")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __float__ must not run")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ must not run")


class HostilePathText:
    def __str__(self):  # pragma: no cover
        raise AssertionError("path text string hook must not run")



def test_stage2114_raw_policy_integer_text_decisions_are_replayable() -> None:
    assert raw_policy_exact_int_text_decision("").reason == "raw_policy_int_text_missing"
    assert raw_policy_exact_int_text_decision("+").reason == "raw_policy_int_sign_without_digits"
    assert raw_policy_exact_int_text_decision("4.5").reason == "raw_policy_int_text_rejected"

    accepted = raw_policy_exact_int_text_decision("+42")
    assert accepted.value == 42
    assert accepted.reason == ""
    assert accepted.replacement_used is False

    HostileNumeric.touched = 0
    value, reason = raw_policy_int(HostileNumeric(), default_value=9, minimum=1, rejected_reason="raw_policy_rejected")
    assert (value, reason) == (9, "raw_policy_rejected")
    assert HostileNumeric.touched == 0



def test_stage2114_context_integer_text_decisions_are_replayable() -> None:
    assert _exact_context_int_text_decision("").reason == "scheduler_context_int_text_missing"
    assert _exact_context_int_text_decision("-").reason == "scheduler_context_int_sign_without_digits"
    assert _exact_context_int_text_decision("1x").reason == "scheduler_context_int_text_rejected"
    assert _exact_context_int_text_decision("-7").value == -7

    HostileNumeric.touched = 0
    value, reason = parse_context_int(HostileNumeric(), default=5, minimum=0)
    assert (value, reason) == (5, "unsupported_scheduler_context_int")
    assert HostileNumeric.touched == 0



def test_stage2114_scheduler_file_metric_decisions_are_replayable_without_hooks() -> None:
    assert _exact_metric_decision(True).reason == "scheduler_file_metric_bool_rejected"
    assert _exact_metric_decision(float("inf")).reason == "scheduler_file_metric_non_finite"
    assert _exact_metric_decision("1.5").reason == "scheduler_file_metric_rejected"
    assert _exact_metric_decision(2).value == 2.0
    assert _exact_metric_decision(2.25).value == 2.25

    HostileNumeric.touched = 0
    assert _exact_metric_decision(HostileNumeric()).reason == "scheduler_file_metric_rejected"
    assert HostileNumeric.touched == 0
    assert scheduler_slow_file_message(elapsed_file=HostileNumeric(), path_text=HostilePathText(), basename=lambda _p: "job.bin") == "SLOW FILE: unavailables job.bin"



def test_stage2114_worker_integer_text_decisions_are_replayable_without_hooks() -> None:
    assert _int_text_decision("").reason == "worker_int_text_missing"
    assert _int_text_decision("+").reason == "worker_int_sign_without_digits"
    assert _int_text_decision("nope").reason == "worker_int_text_rejected"
    assert _int_text_decision("-12").value == -12

    HostileNumeric.touched = 0
    value, reason = worker_int(HostileNumeric(), replacement=11, minimum=0, reason="worker_int_rejected")
    assert (value, reason) == (11, "worker_int_rejected")
    assert HostileNumeric.touched == 0



def test_stage2114_targeted_numeric_helpers_do_not_emit_hidden_none_returns() -> None:
    root = Path(__file__).resolve().parents[1]
    targets = {
        "scheduler/evidence/scheduler_json_writer_support.py": {"_exact_int_text_decision"},
        "scheduler/internal/context_numeric_support.py": {"_exact_context_int_text_decision"},
        "scheduler/execution/scheduler_file_message_support.py": {"_exact_metric_decision"},
        "scheduler/workers/no_hook_scalars.py": {"_int_text_decision"},
    }
    for relative, function_names in targets.items():
        source = (root / relative).read_text(encoding="utf-8")
        tree = ast.parse(source)
        old_helper_names = {"_exact_int_text", "_exact_context_int_text", "_exact_metric", "_int_text"}
        current_function_names = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
        assert old_helper_names.isdisjoint(current_function_names)
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in function_names:
                for child in ast.walk(node):
                    assert not (
                        isinstance(child, ast.Return)
                        and isinstance(child.value, ast.Constant)
                        and child.value.value is None
                    ), f"{relative}:{node.name} still returns hidden None"
