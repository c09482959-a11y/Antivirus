from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.inmemory_empty_drain import requeue_missing_after_empty_drain


class HostileDecision:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __getattribute__(self, name):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError(name)

    def __bool__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("bool")

    def __int__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("int")

    def __iter__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("iter")

    def __repr__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("repr")

    def __str__(self):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("str")

    def __format__(self, spec):  # pragma: no cover - forbidden
        type(self).touched += 1
        raise RuntimeError("format")


def _empty_drain_tree() -> ast.Module:
    root = Path(__file__).resolve().parents[2]
    source = root / "Virus_Scan" / "scheduler" / "queue" / "inmemory_empty_drain.py"
    return parse_python_file(source)


def test_stage1888_empty_drain_rejects_hostile_retry_decision_without_hooks() -> None:
    HostileDecision.reset()

    decision = requeue_missing_after_empty_drain(
        total_files=1,
        terminal=set(),
        retry_callable=lambda _job_id, _reason: HostileDecision(),
    )

    assert decision.retried == 0
    assert decision.failed_now == 1
    assert decision.completed_delta == 0
    assert decision.evidence[0]["error_category"] == "TypeError"
    assert decision.evidence[0]["detail"] == "retry callable returned unsupported decision type HostileDecision"
    assert HostileDecision.touched == 0


def test_stage1888_empty_drain_negative_total_files_uses_static_detail() -> None:
    decision = requeue_missing_after_empty_drain(
        total_files=-2,
        terminal=set(),
        retry_callable=lambda *_args: (_ for _ in ()).throw(AssertionError("should not run")),
    )

    assert decision.evidence[0]["detail"] == "total_files must be non-negative, got -2"


def test_stage1888_empty_drain_has_no_fstrings_or_decision_getattr() -> None:
    tree = _empty_drain_tree()
    joined_strings = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
    getattr_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "getattr"
    ]
    assert joined_strings == []
    assert getattr_calls == []
