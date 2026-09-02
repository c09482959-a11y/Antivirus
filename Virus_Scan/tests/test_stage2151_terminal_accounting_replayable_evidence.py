"""Stage 2151 terminal accounting replayable evidence regressions."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.terminal_accounting_support import durable_results, owned_sequence
from Virus_Scan.scheduler.queue.terminal_accounting_support_evidence import (
    durable_results_decision,
    terminal_accounting_sequence_decision,
)


class HostileTerminalAccountingValue:
    calls = {
        "str": 0,
        "repr": 0,
        "format": 0,
        "iter": 0,
        "len": 0,
        "bool": 0,
    }

    def __str__(self):
        type(self).calls["str"] += 1
        raise RuntimeError("string hook must not run")

    def __repr__(self):
        type(self).calls["repr"] += 1
        raise RuntimeError("repr hook must not run")

    def __format__(self, spec):
        type(self).calls["format"] += 1
        raise RuntimeError("format hook must not run")

    def __iter__(self):
        type(self).calls["iter"] += 1
        raise RuntimeError("iter hook must not run")

    def __len__(self):
        type(self).calls["len"] += 1
        raise RuntimeError("len hook must not run")

    def __bool__(self):
        type(self).calls["bool"] += 1
        raise RuntimeError("bool hook must not run")


def _reset_hooks() -> None:
    for key in HostileTerminalAccountingValue.calls:
        HostileTerminalAccountingValue.calls[key] = 0


def _assert_no_hooks() -> None:
    assert HostileTerminalAccountingValue.calls == {
        "str": 0,
        "repr": 0,
        "format": 0,
        "iter": 0,
        "len": 0,
        "bool": 0,
    }


def test_terminal_accounting_sequence_rejection_is_typed_and_replayable() -> None:
    _reset_hooks()
    hostile = HostileTerminalAccountingValue()
    reports: list[tuple[str, dict[str, object]]] = []

    decision = terminal_accounting_sequence_decision(
        hostile,
        field_name="all_files",
        rejection_reason="queue terminal all_files rejected",
    )
    assert decision.items == ()
    assert decision.accepted is False
    assert dict(decision.evidence)["decision"] == "terminal_accounting_sequence"
    assert dict(decision.evidence)["accepted"] is False

    assert owned_sequence(hostile, field_name="all_files", report=lambda marker, exc, **kwargs: reports.append((marker, kwargs))) == ()
    assert reports[0][0] == "queue_terminal_accounting_sequence_rejected"
    replay = reports[0][1]["extra"]["terminal_accounting_sequence_decision"]
    assert replay["decision"] == "terminal_accounting_sequence"
    assert replay["accepted"] is False
    _assert_no_hooks()


def test_terminal_accounting_durable_result_rejection_is_typed_and_replayable() -> None:
    _reset_hooks()
    hostile = HostileTerminalAccountingValue()
    reports: list[tuple[str, dict[str, object]]] = []

    decision = durable_results_decision(
        hostile,
        materialized=None,
        reason="queue durable results mapping rejected",
    )
    assert decision.results == {}
    assert decision.accepted is False
    assert dict(decision.evidence)["decision"] == "terminal_accounting_durable_results"

    assert durable_results(hostile, report=lambda marker, exc, **kwargs: reports.append((marker, kwargs))) == {}
    assert reports[0][0] == "queue_missing_finalization_result_mapping_rejected"
    replay = reports[0][1]["extra"]["terminal_accounting_durable_results_decision"]
    assert replay["decision"] == "terminal_accounting_durable_results"
    assert replay["accepted"] is False
    _assert_no_hooks()
